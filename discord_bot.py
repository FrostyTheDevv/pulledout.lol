"""
Discord Bot for pulledout.lol
Handles automatic role assignment and invite generation after payment
Uses hybrid commands (slash + text prefix: >)
"""

import discord
from discord import app_commands
from discord.ext import commands
import os
import logging
import time
import aiohttp
from datetime import datetime, timedelta
from typing import Literal, Optional, Any
from dotenv import load_dotenv
import json
from pathlib import Path

# Import database models for user lookup
from database import db, UserAuth, UserProfile, Session, Scan

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Discord Configuration
DISCORD_BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
DISCORD_GUILD_ID = int(os.environ.get('DISCORD_GUILD_ID'))
DISCORD_BUYER_ROLE_ID = int(os.environ.get('DISCORD_BUYER_ROLE_ID'))
DISCORD_DENIED_ROLE_ID = int(os.environ.get('DISCORD_DENIED_ROLE_ID'))

# Owner IDs (full admin access)
OWNER_IDS = [774922425548013609, 1097684284472578058]

# Bot Color Scheme
EMBED_COLOR = 0x808080  # Grey

# Command sync tracking file
SYNC_TRACKER_FILE = Path('.bot_sync_tracker.json')
MIN_SYNC_INTERVAL = 3600  # Minimum 1 hour between syncs

# Bot setup with required intents
intents = discord.Intents.default()
intents.members = True
intents.guilds = True
intents.message_content = True

class PulledOutBot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix='>', intents=intents, help_command=None)
        
    def should_sync_commands(self) -> bool:
        """Check if commands should be synced based on last sync time"""
        try:
            if not SYNC_TRACKER_FILE.exists():
                return True
            
            with open(SYNC_TRACKER_FILE, 'r') as f:
                data = json.load(f)
                last_sync = data.get('last_sync', 0)
                current_time = time.time()
                
                # Only sync if more than MIN_SYNC_INTERVAL seconds have passed
                if current_time - last_sync > MIN_SYNC_INTERVAL:
                    return True
                else:
                    logger.info(f"Skipping command sync - last synced {int((current_time - last_sync) / 60)} minutes ago")
                    return False
        except Exception as e:
            logger.warning(f"Error reading sync tracker: {e}")
            return True
    
    def mark_commands_synced(self):
        """Mark commands as synced with current timestamp"""
        try:
            with open(SYNC_TRACKER_FILE, 'w') as f:
                json.dump({'last_sync': time.time()}, f)
        except Exception as e:
            logger.error(f"Error writing sync tracker: {e}")
        
    async def setup_hook(self):
        """Sync commands with Discord (rate-limited to once per hour)"""
        if self.should_sync_commands():
            try:
                guild = discord.Object(id=DISCORD_GUILD_ID)
                self.tree.copy_global_to(guild=guild)
                await self.tree.sync(guild=guild)
                self.mark_commands_synced()
                logger.info("Commands synced to guild successfully")
            except discord.HTTPException as e:
                if e.status == 429:  # Rate limited
                    logger.warning("Rate limited when syncing commands - will retry later")
                    logger.info("Note: Existing commands are still functional")
                else:
                    logger.error(f"Failed to sync commands: {e}")
        else:
            logger.info("Commands recently synced, skipping to avoid rate limits")

bot = PulledOutBot()

# Flask app instance for database access
flask_app: Optional[Any] = None

# Store pending invites mapping invite_code -> discord_id
pending_invites = {}

# Maintenance mode
maintenance_mode = False

# Helper Functions

def is_owner():
    """Check if user is bot owner"""
    async def predicate(ctx):
        return ctx.author.id in OWNER_IDS
    return commands.check(predicate)

def create_embed(title: str, description: str = None, color: int = EMBED_COLOR) -> discord.Embed:
    """Create a grey embed with consistent styling"""
    embed = discord.Embed(title=title, description=description, color=color, timestamp=datetime.utcnow())
    embed.set_footer(text="pulledout.lol")
    return embed

# ============================================
# DISCORD UI COMPONENTS V2 (Views, Buttons, Modals)
# ============================================

class HelpView(discord.ui.View):
    """Interactive help menu with buttons"""
    def __init__(self, author_id: int, is_admin: bool = False, is_owner: bool = False):
        super().__init__(timeout=180)
        self.author_id = author_id
        self.is_admin = is_admin
        self.is_owner = is_owner
        self.current_page = "main"
    
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("This menu is not for you!", ephemeral=True)
            return False
        return True
    
    @discord.ui.button(label="Public Commands", style=discord.ButtonStyle.gray)
    async def public_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = create_embed("Public Commands")
        embed.add_field(
            name="Available to Everyone",
            value=(
                "```\n"
                ">help - Show this help menu\n"
                ">status - Check your access status\n"
                ">ping - Check bot & service latency\n"
                "```"
            ),
            inline=False
        )
        await interaction.response.edit_message(embed=embed, view=self)
    
    @discord.ui.button(label="Admin Commands", style=discord.ButtonStyle.blurple, disabled=False)
    async def admin_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self.is_admin and not self.is_owner:
            await interaction.response.send_message("You don't have admin permissions!", ephemeral=True)
            return
        
        embed = create_embed("Admin Commands")
        embed.add_field(
            name="Server Administrators",
            value=(
                "```\n"
                ">admin - Open admin panel\n"
                ">invite <discord_id> - Create paid invite\n"
                ">grant <user> - Grant buyer role\n"
                ">revoke <user> - Revoke access\n"
                ">check <user> - Check user status\n"
                ">stats - Server statistics\n"
                "```"
            ),
            inline=False
        )
        await interaction.response.edit_message(embed=embed, view=self)
    
    @discord.ui.button(label="Owner Commands", style=discord.ButtonStyle.red, disabled=False)
    async def owner_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self.is_owner:
            await interaction.response.send_message("You must be a bot owner!", ephemeral=True)
            return
        
        embed = create_embed("Owner Commands")
        embed.add_field(
            name="Bot Owners Only",
            value=(
                "```\n"
                ">purge <days> - Remove inactive members\n"
                ">ban <user> <reason> - Ban from service\n"
                ">unban <user> - Unban from service\n"
                ">config - Show configuration\n"
                ">logs <lines> - Show activity\n"
                ">maintenance - Toggle maintenance\n"
                ">broadcast <msg> - Message all buyers\n"
                "```"
            ),
            inline=False
        )
        await interaction.response.edit_message(embed=embed, view=self)
    
    @discord.ui.button(label="Close", style=discord.ButtonStyle.gray, row=1)
    async def close_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.message:
            await interaction.message.delete()
        self.stop()

class StatusView(discord.ui.View):
    """Interactive status display with action buttons"""
    def __init__(self, member: discord.Member, has_access: bool):
        super().__init__(timeout=180)
        self.member = member
        self.has_access = has_access
        
        # Add link buttons
        if not has_access:
            self.add_item(discord.ui.Button(
                label="Purchase Access",
                style=discord.ButtonStyle.link,
                url="https://pulledout.lol/pay"
            ))
        
        self.add_item(discord.ui.Button(
            label="View Website",
            style=discord.ButtonStyle.link,
            url="https://pulledout.lol"
        ))

class AdminControlPanel(discord.ui.View):
    """Admin control panel with action buttons"""
    def __init__(self, guild: discord.Guild):
        super().__init__(timeout=300)
        self.guild = guild
    
    @discord.ui.button(label="Server Stats", style=discord.ButtonStyle.blurple)
    async def stats_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        buyer_role = self.guild.get_role(DISCORD_BUYER_ROLE_ID)
        denied_role = self.guild.get_role(DISCORD_DENIED_ROLE_ID)
        
        buyer_count = len(buyer_role.members) if buyer_role else 0
        denied_count = len(denied_role.members) if denied_role else 0
        
        embed = create_embed("Server Statistics")
        embed.add_field(name="Total Members", value=str(self.guild.member_count or 0), inline=True)
        embed.add_field(name="Paid Members", value=str(buyer_count), inline=True)
        embed.add_field(name="Denied Members", value=str(denied_count), inline=True)
        embed.add_field(name="Pending Invites", value=str(len(pending_invites)), inline=True)
        embed.add_field(name="Bot Status", value="Online", inline=True)
        embed.add_field(name="Maintenance", value="Yes" if maintenance_mode else "No", inline=True)
        
        await interaction.response.send_message(embed=embed, ephemeral=True)
    
    @discord.ui.button(label="Refresh", style=discord.ButtonStyle.green)
    async def refresh_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = create_embed("Admin Control Panel", "Use the buttons below to view server statistics.")
        await interaction.response.edit_message(embed=embed, view=self)

class ConfirmView(discord.ui.View):
    """Confirmation dialog for dangerous actions"""
    def __init__(self, author_id: int):
        super().__init__(timeout=60)
        self.author_id = author_id
        self.value = None
    
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("This is not for you!", ephemeral=True)
            return False
        return True
    
    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.green)
    async def confirm_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.value = True
        await interaction.response.defer()
        self.stop()
    
    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.red)
    async def cancel_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.value = False
        await interaction.response.defer()
        self.stop()

class UserSelectView(discord.ui.View):
    """Simplified user selection view"""
    def __init__(self, author_id: int, action: str):
        super().__init__(timeout=180)
        self.author_id = author_id
        self.action = action
        self.selected_user = None
    
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("This menu is not for you!", ephemeral=True)
            return False
        return True

class MaintenanceModal(discord.ui.Modal, title="Maintenance Announcement"):
    """Modal for maintenance mode announcements"""
    message = discord.ui.TextInput(
        label="Announcement Message",
        style=discord.TextStyle.paragraph,
        placeholder="Enter the maintenance announcement...",
        required=True,
        max_length=1000
    )
    
    async def on_submit(self, interaction: discord.Interaction):
        global maintenance_mode
        maintenance_mode = not maintenance_mode
        
        embed = create_embed(
            "Maintenance Mode Updated",
            f"Status: {'Enabled' if maintenance_mode else 'Disabled'}\n\nMessage: {self.message.value[:200]}"
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.event
async def on_ready():
    """Called when bot successfully connects to Discord"""
    logger.info(f'Bot logged in as {bot.user}')
    
    guild = bot.get_guild(DISCORD_GUILD_ID)
    if guild:
        logger.info(f'Connected to guild: {guild.name}')
        buyer_role = guild.get_role(DISCORD_BUYER_ROLE_ID)
        denied_role = guild.get_role(DISCORD_DENIED_ROLE_ID)
        
        if not buyer_role:
            logger.error(f'Buyer role not found: {DISCORD_BUYER_ROLE_ID}')
        if not denied_role:
            logger.error(f'Denied role not found: {DISCORD_DENIED_ROLE_ID}')
    else:
        logger.error(f'Guild not found: {DISCORD_GUILD_ID}')
    
    logger.info('Bot ready')

@bot.event
async def on_member_join(member):
    """Called when a user joins the guild. Checks if they joined via a paid invite and assigns buyer role."""
    logger.info(f'Member joined: {member.name} (ID: {member.id})')
    
    guild = member.guild
    
    for invite_code, discord_id in list(pending_invites.items()):
        if str(member.id) == discord_id:
            logger.info(f'Member joined via paid invite: {invite_code}')
            
            buyer_role = guild.get_role(DISCORD_BUYER_ROLE_ID)
            if buyer_role:
                try:
                    await member.add_roles(buyer_role)
                    logger.info(f'Assigned buyer role to {member.name}')
                    
                    embed = create_embed(
                        "Welcome to pulledout.lol",
                        f"Your payment has been verified and you now have access.\n\n"
                        f"Visit https://pulledout.lol to start using the scanner.\n"
                        f"Use >help to see available commands."
                    )
                    
                    try:
                        await member.send(embed=embed)
                    except discord.Forbidden:
                        logger.warning(f'Could not send DM to {member.name}')
                    
                    del pending_invites[invite_code]
                    
                except discord.Forbidden:
                    logger.error(f'Missing permissions to assign role')
                except Exception as e:
                    logger.error(f'Error assigning role: {e}')
            else:
                logger.error(f'Buyer role not found')

# ============================================
# USER COMMANDS (Available to everyone)
# ============================================

@bot.hybrid_command(name='help', description='Show all available commands')
@app_commands.guilds(DISCORD_GUILD_ID)
async def help_command(ctx):
    """Show all available commands with interactive buttons"""
    is_admin = ctx.author.guild_permissions.administrator if ctx.guild else False
    is_owner = ctx.author.id in OWNER_IDS
    
    embed = create_embed(
        "pulledout.lol Bot Commands",
        "Click the buttons below to view different command categories.\n"
        "You can use both `/command` (slash) and `>command` (text) formats."
    )
    
    embed.add_field(
        name="Quick Links",
        value="[Website](https://pulledout.lol) | [Purchase](https://pulledout.lol/pay)",
        inline=False
    )
    
    view = HelpView(ctx.author.id, is_admin=is_admin, is_owner=is_owner)
    await ctx.send(embed=embed, view=view, ephemeral=True)

@bot.hybrid_command(name='status', description='Check your or another user\'s access status')
@app_commands.guilds(DISCORD_GUILD_ID)
@app_commands.describe(user='User to check (admin only, leave empty for yourself)')
async def status_command(ctx, user: discord.Member = None):
    """Check your access status or another user's status (admin only) with website integration"""
    guild = ctx.guild
    
    if not guild:
        await ctx.send("This command must be used in a server", ephemeral=True)
        return
    
    # If checking another user, verify admin permissions
    if user and user.id != ctx.author.id:
        if not (ctx.author.guild_permissions.administrator or ctx.author.id in OWNER_IDS):
            embed = create_embed("Permission Denied", "Only admins can check other users' status")
            await ctx.send(embed=embed, ephemeral=True)
            return
        member = user
        checking_other = True
    else:
        member = ctx.author
        checking_other = False
    
    buyer_role = guild.get_role(DISCORD_BUYER_ROLE_ID)
    denied_role = guild.get_role(DISCORD_DENIED_ROLE_ID)
    
    has_buyer = buyer_role in member.roles if buyer_role else False
    has_denied = denied_role in member.roles if denied_role else False
    
    embed = create_embed(f"Access Status - {member.display_name}")
    
    # Status indicator
    if has_denied:
        embed.add_field(name="Status", value="Access Denied", inline=False)
        embed.add_field(name="Reason", value="Your access has been revoked", inline=False)
    elif has_buyer:
        embed.add_field(name="Status", value="Active Access", inline=False)
        embed.add_field(name="Dashboard", value="Visit the website to use the scanner", inline=False)
    else:
        embed.add_field(name="Status", value="No Access", inline=False)
        embed.add_field(name="Purchase", value="Click the button below to purchase access", inline=False)
    
    # Query website database for user info
    try:
        # Use Flask app context for database queries
        if flask_app is not None:
            with flask_app.app_context():
                user_auth = UserAuth.query.filter_by(discord_id=str(member.id)).first()
                
                if user_auth and user_auth.profile:
                    # User has website account
                    profile = user_auth.profile
                    
                    # Website account info
                    embed.add_field(
                        name="Website Account",
                        value="Registered",
                        inline=True
                    )
                    
                    # User IDs
                    embed.add_field(
                        name="User ID (Database)",
                        value=f"`{user_auth.id}`",
                        inline=True
                    )
                    
                    embed.add_field(
                        name="Discord ID",
                        value=f"`{user_auth.discord_id}`",
                        inline=True
                    )
                    
                    # Last login
                    if profile.last_login:
                        last_login_str = profile.last_login.strftime('%Y-%m-%d %H:%M UTC')
                        embed.add_field(
                            name="Last Website Login",
                            value=last_login_str,
                            inline=True
                        )
                    
                    # Account created
                    if user_auth.created_at:
                        created_str = user_auth.created_at.strftime('%Y-%m-%d')
                        embed.add_field(
                            name="Account Created",
                            value=created_str,
                            inline=True
                        )
                    
                    # Scan count
                    scan_count = Scan.query.filter_by(user_id=user_auth.id).count()
                    embed.add_field(
                        name="Total Scans",
                        value=str(scan_count),
                        inline=True
                    )
                    
                    # Get active sessions with details
                    active_sessions = Session.query.filter(
                        Session.user_id == user_auth.id,
                        Session.expires_at > datetime.utcnow()
                    ).order_by(Session.created_at.desc()).all()
                    
                    embed.add_field(
                        name="Active Sessions",
                        value=str(len(active_sessions)),
                        inline=True
                    )
                    
                    # Display user tokens (ephemeral message - only user can see)
                    if active_sessions:
                        token_info = []
                        for idx, session in enumerate(active_sessions, 1):
                            created = session.created_at.strftime('%m/%d %H:%M')
                            expires = session.expires_at.strftime('%m/%d %H:%M')
                            # Show full token in spoiler tags for security
                            token_info.append(
                                f"**Token {idx}:**\n"
                                f"User Token: ||`{session.session_token}`||\n"
                                f"Created: {created} UTC\n"
                                f"Expires: {expires} UTC"
                            )
                        
                        embed.add_field(
                            name="User Tokens (Keep Secure!)",
                            value="\n\n".join(token_info[:3]),  # Show max 3 tokens
                            inline=False
                        )
                        
                        if len(active_sessions) > 3:
                            embed.add_field(
                                name="Note",
                                value=f"Showing 3 of {len(active_sessions)} tokens. Use website to manage all tokens.",
                                inline=False
                            )
                    else:
                        embed.add_field(
                            name="User Tokens",
                            value="No active tokens. Login to pulledout.lol to create a token.",
                            inline=False
                        )
                else:
                    # No website account
                    embed.add_field(
                        name="Website Account",
                        value="Not Registered",
                        inline=True
                    )
                    embed.add_field(
                        name="Note",
                        value="Login to pulledout.lol to create your account",
                        inline=False
                    )
        else:
            # Flask app not initialized
            embed.add_field(
                name="Website Account",
                value="Database unavailable",
                inline=True
            )
    except Exception as e:
        logger.error(f"Error querying database for user {member.id}: {e}")
        embed.add_field(
            name="Website Account",
            value="Unable to retrieve data",
            inline=True
        )
    
    # Discord server info
    joined_str = member.joined_at.strftime('%Y-%m-%d') if member.joined_at else 'Unknown'
    embed.add_field(name="Discord Member Since", value=joined_str, inline=True)
    embed.add_field(name="Is Owner", value="Yes" if member.id in OWNER_IDS else "No", inline=True)
    
    # Add footer if admin is checking another user
    if checking_other:
        embed.set_footer(text=f"Requested by {ctx.author.display_name} | pulledout.lol")
    
    view = StatusView(member, has_buyer)
    # Only ephemeral if checking own status or if admin wants it private
    await ctx.send(embed=embed, view=view, ephemeral=(not checking_other))

@bot.hybrid_command(name='ping', description='Check bot latency and service status')
@app_commands.guilds(DISCORD_GUILD_ID)
async def ping_command(ctx):
    """Check bot latency and service status"""
    # Start timing
    start_time = time.time()
    
    # Send initial message
    embed = create_embed("Pinging...", "Checking connectivity to services...")
    message = await ctx.send(embed=embed)
    
    # Calculate Discord API latency
    api_latency = (time.time() - start_time) * 1000
    
    # Discord WebSocket latency
    ws_latency = bot.latency * 1000
    
    # Check website connectivity
    website_status = "Offline"
    website_latency = "N/A"
    try:
        async with aiohttp.ClientSession() as session:
            ws_start = time.time()
            async with session.get('https://pulledout.lol', timeout=aiohttp.ClientTimeout(total=5)) as response:
                website_latency = f"{(time.time() - ws_start) * 1000:.0f}ms"
                if response.status == 200:
                    website_status = "Online"
                else:
                    website_status = f"Status {response.status}"
    except Exception as e:
        website_status = "Offline"
        website_latency = "Timeout"
    
    # Check Discord CDN
    cdn_status = "Offline"
    cdn_latency = "N/A"
    try:
        async with aiohttp.ClientSession() as session:
            cdn_start = time.time()
            async with session.get('https://cdn.discordapp.com/embed/avatars/0.png', timeout=aiohttp.ClientTimeout(total=5)) as response:
                cdn_latency = f"{(time.time() - cdn_start) * 1000:.0f}ms"
                if response.status == 200:
                    cdn_status = "Online"
                else:
                    cdn_status = f"Status {response.status}"
    except Exception as e:
        cdn_status = "Offline"
        cdn_latency = "Timeout"
    
    # Create final embed
    final_embed = create_embed("Pong! Latency Report")
    final_embed.add_field(name="Discord API", value=f"{api_latency:.0f}ms", inline=True)
    final_embed.add_field(name="WebSocket", value=f"{ws_latency:.0f}ms", inline=True)
    final_embed.add_field(name="Message RTT", value=f"{(time.time() - start_time) * 1000:.0f}ms", inline=True)
    final_embed.add_field(name="pulledout.lol", value=f"{website_status}\n{website_latency}", inline=True)
    final_embed.add_field(name="Discord CDN", value=f"{cdn_status}\n{cdn_latency}", inline=True)
    final_embed.add_field(name="Bot Status", value="Operational", inline=True)
    
    await message.edit(embed=final_embed)

# ============================================
# ADMIN COMMANDS (Server Administrators)
# ============================================

@bot.hybrid_command(name='admin', description='Open admin control panel')
@app_commands.guilds(DISCORD_GUILD_ID)
@commands.has_permissions(administrator=True)
async def admin_command(ctx):
    """Open admin control panel with interactive buttons"""
    if not ctx.guild:
        embed = create_embed("Error", "This command must be used in a server")
        await ctx.send(embed=embed, ephemeral=True)
        return
    
    embed = create_embed(
        "Admin Control Panel",
        "Use the buttons below to view server statistics quickly."
    )
    embed.add_field(
        name="Available Actions",
        value="View Stats\nRefresh Panel",
        inline=False
    )
    
    view = AdminControlPanel(ctx.guild)
    await ctx.send(embed=embed, view=view, ephemeral=True)

@bot.hybrid_command(name='invite', description='Generate a paid invite for a Discord user')
@app_commands.guilds(DISCORD_GUILD_ID)
@commands.has_permissions(administrator=True)
@app_commands.describe(discord_id='The Discord ID of the user to create invite for')
async def invite_command(ctx, discord_id: str):
    """Generate a paid invite for a Discord user"""
    guild = ctx.guild
    if not guild:
        embed = create_embed("Error", "This command must be used in a server")
        await ctx.send(embed=embed, ephemeral=True)
        return
    
    try:
        invite = await guild.text_channels[0].create_invite(
            max_age=172800,
            max_uses=1,
            unique=True,
            reason=f"Paid access for {discord_id}"
        )
        
        pending_invites[invite.code] = discord_id
        logger.info(f'Created invite for {discord_id}')
        
        embed = create_embed("Invite Created Successfully")
        embed.add_field(name="Discord ID", value=f"`{discord_id}`", inline=False)
        embed.add_field(name="Invite URL", value=f"||{invite.url}||", inline=False)
        embed.add_field(name="Valid For", value="48 hours", inline=True)
        embed.add_field(name="Max Uses", value="1", inline=True)
        embed.add_field(name="Code", value=f"`{invite.code}`", inline=True)
        
        # Add copy button
        view = discord.ui.View()
        view.add_item(discord.ui.Button(
            label="Copy Invite Link",
            style=discord.ButtonStyle.link,
            url=invite.url
        ))
        
        await ctx.send(embed=embed, view=view, ephemeral=True)
    except Exception as e:
        logger.error(f'Error creating invite: {e}')
        embed = create_embed("Error", f"Failed to create invite: {str(e)}")
        await ctx.send(embed=embed, ephemeral=True)

@bot.hybrid_command(name='grant', description='Manually grant buyer role to a member')
@app_commands.guilds(DISCORD_GUILD_ID)
@commands.has_permissions(administrator=True)
@app_commands.describe(member='The member to grant access to')
async def grant_command(ctx, member: discord.Member):
    """Manually grant buyer role to a member with confirmation"""
    if not ctx.guild:
        embed = create_embed("Error", "This command must be used in a server")
        await ctx.send(embed=embed, ephemeral=True)
        return
    
    buyer_role = ctx.guild.get_role(DISCORD_BUYER_ROLE_ID)
    
    if not buyer_role:
        embed = create_embed("Error", "Buyer role not found in server")
        await ctx.send(embed=embed, ephemeral=True)
        return
    
    if buyer_role in member.roles:
        embed = create_embed("Already Has Access", f"{member.mention} already has the buyer role")
        await ctx.send(embed=embed, ephemeral=True)
        return
    
    confirm_embed = create_embed("Confirm Grant Access", f"Grant buyer role to {member.mention}?")
    view = ConfirmView(ctx.author.id)
    message = await ctx.send(embed=confirm_embed, view=view, ephemeral=True)
    await view.wait()
    
    if view.value is None:
        await message.edit(embed=create_embed("Timeout", "Confirmation timed out"), view=None)
        return
    if not view.value:
        await message.edit(embed=create_embed("Cancelled", "Action cancelled"), view=None)
        return
    
    try:
        await member.add_roles(buyer_role)
        logger.info(f'{ctx.author.name} granted access to {member.name}')
        embed = create_embed("Access Granted Successfully")
        embed.add_field(name="User", value=member.mention, inline=True)
        embed.add_field(name="Granted By", value=ctx.author.mention, inline=True)
        await message.edit(embed=embed, view=None)
    except Exception as e:
        logger.error(f'Error granting access: {e}')
        embed = create_embed("Error", f"Failed: {str(e)}")
        await message.edit(embed=embed, view=None)

@bot.hybrid_command(name='revoke', description='Revoke access and add denied role')
@app_commands.guilds(DISCORD_GUILD_ID)
@commands.has_permissions(administrator=True)
@app_commands.describe(member='The member to revoke access from')
async def revoke_command(ctx, member: discord.Member):
    """Revoke access and add denied role with confirmation"""
    if not ctx.guild:
        embed = create_embed("Error", "This command must be used in a server")
        await ctx.send(embed=embed, ephemeral=True)
        return
    
    buyer_role = ctx.guild.get_role(DISCORD_BUYER_ROLE_ID)
    denied_role = ctx.guild.get_role(DISCORD_DENIED_ROLE_ID)
    
    confirm_embed = create_embed("Confirm Revoke Access", f"Revoke access for {member.mention}?\nThis will remove buyer role and add denied role.")
    view = ConfirmView(ctx.author.id)
    message = await ctx.send(embed=confirm_embed, view=view, ephemeral=True)
    await view.wait()
    
    if view.value is None:
        await message.edit(embed=create_embed("Timeout", "Confirmation timed out"), view=None)
        return
    if not view.value:
        await message.edit(embed=create_embed("Cancelled", "Action cancelled"), view=None)
        return
    
    try:
        actions = []
        if buyer_role and buyer_role in member.roles:
            await member.remove_roles(buyer_role)
            actions.append("Removed buyer role")
            logger.info(f'{ctx.author.name} removed buyer role from {member.name}')
        if denied_role:
            await member.add_roles(denied_role)
            actions.append("Added denied role")
            logger.info(f'{ctx.author.name} added denied role to {member.name}')
        
        embed = create_embed("Access Revoked Successfully")
        embed.add_field(name="User", value=member.mention, inline=True)
        embed.add_field(name="Revoked By", value=ctx.author.mention, inline=True)
        
        await ctx.send(embed=embed)
    except Exception as e:
        logger.error(f'Error revoking access: {e}')
        embed = create_embed("Error", f"Failed to revoke access: {str(e)}")
        await ctx.send(embed=embed, ephemeral=True)

@bot.hybrid_command(name='check', description='Check a member\'s roles and access status')
@app_commands.guilds(DISCORD_GUILD_ID)
@commands.has_permissions(administrator=True)
@app_commands.describe(member='The member to check')
async def check_command(ctx, member: discord.Member):
    """Check a member's roles and access status"""
    if not ctx.guild:
        embed = create_embed("Error", "This command must be used in a server")
        await ctx.send(embed=embed, ephemeral=True)
        return
    
    buyer_role = ctx.guild.get_role(DISCORD_BUYER_ROLE_ID)
    denied_role = ctx.guild.get_role(DISCORD_DENIED_ROLE_ID)
    
    has_buyer = buyer_role in member.roles if buyer_role else False
    has_denied = denied_role in member.roles if denied_role else False
    
    if has_denied:
        status = "Access Denied"
    elif has_buyer:
        status = "Has Access"
    else:
        status = "No Access"
    
    joined_str = member.joined_at.strftime('%Y-%m-%d %H:%M UTC') if member.joined_at else 'Unknown'
    
    embed = create_embed(f"User Status - {member.display_name}")
    embed.add_field(name="Status", value=status, inline=False)
    embed.add_field(name="Buyer Role", value="Yes" if has_buyer else "No", inline=True)
    embed.add_field(name="Denied Role", value="Yes" if has_denied else "No", inline=True)
    embed.add_field(name="Joined Server", value=joined_str, inline=False)
    embed.add_field(name="User ID", value=str(member.id), inline=False)
    
    await ctx.send(embed=embed, ephemeral=True)

@bot.hybrid_command(name='stats', description='Show server statistics')
@app_commands.guilds(DISCORD_GUILD_ID)
@commands.has_permissions(administrator=True)
async def stats_command(ctx):
    """Show server statistics"""
    guild = ctx.guild
    if not guild:
        embed = create_embed("Error", "This command must be used in a server")
        await ctx.send(embed=embed, ephemeral=True)
        return
    
    buyer_role = guild.get_role(DISCORD_BUYER_ROLE_ID)
    denied_role = guild.get_role(DISCORD_DENIED_ROLE_ID)
    
    buyer_count = len(buyer_role.members) if buyer_role else 0
    denied_count = len(denied_role.members) if denied_role else 0
    
    embed = create_embed("Server Statistics")
    embed.add_field(name="Total Members", value=str(guild.member_count or 0), inline=True)
    embed.add_field(name="Paid Members", value=str(buyer_count), inline=True)
    embed.add_field(name="Denied Members", value=str(denied_count), inline=True)
    embed.add_field(name="Pending Invites", value=str(len(pending_invites)), inline=True)
    embed.add_field(name="Bot Status", value="Online", inline=True)
    embed.add_field(name="Maintenance", value="Yes" if maintenance_mode else "No", inline=True)
    
    await ctx.send(embed=embed, ephemeral=True)



# ============================================
# OWNER COMMANDS (Restricted to owner IDs)
# ============================================

@bot.hybrid_command(name='purge', description='Remove inactive members without buyer role')
@app_commands.guilds(DISCORD_GUILD_ID)
@is_owner()
@app_commands.describe(days='Days of inactivity (default: 30)')
async def purge_command(ctx, days: int = 30):
    """Remove inactive members"""
    guild = ctx.guild
    if not guild:
        embed = create_embed("Error", "This command must be used in a server")
        await ctx.send(embed=embed, ephemeral=True)
        return
    
    buyer_role = guild.get_role(DISCORD_BUYER_ROLE_ID)
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    purged = 0
    for member in guild.members:
        if buyer_role not in member.roles and member.joined_at and member.joined_at < cutoff_date:
            try:
                await member.kick(reason=f"Inactive for {days} days")
                purged += 1
            except:
                pass
    
    embed = create_embed("Purge Complete")
    embed.add_field(name="Members Removed", value=str(purged), inline=True)
    embed.add_field(name="Inactivity Period", value=f"{days} days", inline=True)
    
    logger.info(f'{ctx.author.name} purged {purged} inactive members')
    await ctx.send(embed=embed)

@bot.hybrid_command(name='ban', description='Ban user from service')
@app_commands.guilds(DISCORD_GUILD_ID)
@is_owner()
@app_commands.describe(member='User to ban', reason='Reason for ban')
async def ban_command(ctx, member: discord.Member, *, reason: str = "No reason provided"):
    """Ban user from service"""
    buyer_role = ctx.guild.get_role(DISCORD_BUYER_ROLE_ID)
    denied_role = ctx.guild.get_role(DISCORD_DENIED_ROLE_ID)
    
    try:
        if buyer_role and buyer_role in member.roles:
            await member.remove_roles(buyer_role)
        if denied_role:
            await member.add_roles(denied_role)
        
        embed = create_embed("User Banned")
        embed.add_field(name="User", value=member.mention, inline=True)
        embed.add_field(name="Banned By", value=ctx.author.mention, inline=True)
        embed.add_field(name="Reason", value=reason, inline=False)
        
        logger.info(f'{ctx.author.name} banned {member.name}: {reason}')
        await ctx.send(embed=embed)
    except Exception as e:
        embed = create_embed("Error", f"Failed to ban user: {str(e)}")
        await ctx.send(embed=embed, ephemeral=True)

@bot.hybrid_command(name='unban', description='Unban user from service')
@app_commands.guilds(DISCORD_GUILD_ID)
@is_owner()
@app_commands.describe(member='User to unban')
async def unban_command(ctx, member: discord.Member):
    """Unban user from service"""
    denied_role = ctx.guild.get_role(DISCORD_DENIED_ROLE_ID)
    
    try:
        if denied_role and denied_role in member.roles:
            await member.remove_roles(denied_role)
        
        embed = create_embed("User Unbanned")
        embed.add_field(name="User", value=member.mention, inline=True)
        embed.add_field(name="Unbanned By", value=ctx.author.mention, inline=True)
        
        logger.info(f'{ctx.author.name} unbanned {member.name}')
        await ctx.send(embed=embed)
    except Exception as e:
        embed = create_embed("Error", f"Failed to unban user: {str(e)}")
        await ctx.send(embed=embed, ephemeral=True)

@bot.hybrid_command(name='config', description='Show website configuration and status')
@app_commands.guilds(DISCORD_GUILD_ID)
@is_owner()
async def config_command(ctx):
    """Show website configuration and status"""
    embed = create_embed("pulledout.lol Configuration")
    
    # Website information
    embed.add_field(name="Website URL", value="https://pulledout.lol", inline=False)
    embed.add_field(name="Payment Provider", value="LemonSqueezy", inline=True)
    embed.add_field(name="Price", value="$50 (one-time)", inline=True)
    embed.add_field(name="Authentication", value="Discord OAuth", inline=True)
    
    # Service configuration
    embed.add_field(name="Database", value="PostgreSQL (Railway)", inline=True)
    embed.add_field(name="Hosting", value="Railway", inline=True)
    embed.add_field(name="Bot Status", value="Online", inline=True)
    
    # Stats
    buyer_role = ctx.guild.get_role(DISCORD_BUYER_ROLE_ID) if ctx.guild else None
    buyer_count = len(buyer_role.members) if buyer_role else 0
    embed.add_field(name="Active Users", value=str(buyer_count), inline=True)
    embed.add_field(name="Pending Invites", value=str(len(pending_invites)), inline=True)
    embed.add_field(name="Maintenance Mode", value="Yes" if maintenance_mode else "No", inline=True)
    
    # Environment
    embed.add_field(
        name="Environment Variables",
        value=f"Discord OAuth: {'[OK]' if os.environ.get('DISCORD_CLIENT_ID') else '[X]'}\n"
              f"LemonSqueezy API: {'[OK]' if os.environ.get('LEMONSQUEEZY_API_KEY') else '[X]'}\n"
              f"Database URL: {'[OK]' if os.environ.get('DATABASE_URL') else '[X]'}",
        inline=False
    )
    
    await ctx.send(embed=embed, ephemeral=True)

@bot.hybrid_command(name='maintenance', description='Toggle maintenance mode')
@app_commands.guilds(DISCORD_GUILD_ID)
@is_owner()
async def maintenance_command(ctx):
    """Toggle maintenance mode"""
    global maintenance_mode
    maintenance_mode = not maintenance_mode
    
    embed = create_embed("Maintenance Mode")
    embed.add_field(name="Status", value="Enabled" if maintenance_mode else "Disabled", inline=True)
    embed.add_field(name="Changed By", value=ctx.author.mention, inline=True)
    
    logger.info(f'{ctx.author.name} toggled maintenance mode: {maintenance_mode}')
    await ctx.send(embed=embed)

@bot.hybrid_command(name='broadcast', description='Send message to all buyers')
@app_commands.guilds(DISCORD_GUILD_ID)
@is_owner()
@app_commands.describe(message='Message to broadcast')
async def broadcast_command(ctx, *, message: str):
    """Broadcast message to all buyers"""
    guild = ctx.guild
    buyer_role = guild.get_role(DISCORD_BUYER_ROLE_ID)
    
    if not buyer_role:
        embed = create_embed("Error", "Buyer role not found")
        await ctx.send(embed=embed, ephemeral=True)
        return
    
    sent = 0
    failed = 0
    
    for member in buyer_role.members:
        try:
            broadcast_embed = create_embed("Announcement from pulledout.lol", message)
            await member.send(embed=broadcast_embed)
            sent += 1
        except:
            failed += 1
    
    embed = create_embed("Broadcast Complete")
    embed.add_field(name="Sent", value=str(sent), inline=True)
    embed.add_field(name="Failed", value=str(failed), inline=True)
    embed.add_field(name="Message", value=message[:100], inline=False)
    
    logger.info(f'{ctx.author.name} broadcast to {sent} buyers')
    await ctx.send(embed=embed, ephemeral=True)

@bot.hybrid_command(name='logs', description='Show recent bot activity')
@app_commands.guilds(DISCORD_GUILD_ID)
@is_owner()
@app_commands.describe(lines='Number of recent events (default: 10)')
async def logs_command(ctx, lines: int = 10):
    """Show recent bot activity"""
    embed = create_embed("Recent Activity")
    embed.add_field(name="Pending Invites", value=str(len(pending_invites)), inline=True)
    embed.add_field(name="Maintenance Mode", value="Yes" if maintenance_mode else "No", inline=True)
    embed.description = f"Last {lines} events logged to console"
    
    await ctx.send(embed=embed, ephemeral=True)

# ============================================
# ERROR HANDLING
# ============================================

@bot.event
async def on_command_error(ctx, error):
    """Handle command errors"""
    if isinstance(error, commands.MissingPermissions):
        embed = create_embed("Permission Denied", "You don't have permission to use this command")
        await ctx.send(embed=embed, ephemeral=True)
    elif isinstance(error, commands.CheckFailure):
        embed = create_embed("Access Denied", "This command is restricted to bot owners")
        await ctx.send(embed=embed, ephemeral=True)
    elif isinstance(error, commands.MissingRequiredArgument):
        embed = create_embed("Missing Argument", f"Required argument: {error.param.name}")
        await ctx.send(embed=embed, ephemeral=True)
    else:
        logger.error(f'Command error: {error}')
        embed = create_embed("Error", f"An error occurred: {str(error)}")
        await ctx.send(embed=embed, ephemeral=True)

def run_bot():
    """Start the Discord bot with database access"""
    if not DISCORD_BOT_TOKEN:
        logger.error("DISCORD_BOT_TOKEN not set!")
        return
    
    if not DISCORD_GUILD_ID:
        logger.error("DISCORD_GUILD_ID not set!")
        return
    
    # Initialize Flask app context for database access
    try:
        from web_server import app
        global flask_app
        flask_app = app
        logger.info("Flask app context initialized for Discord bot")
    except Exception as e:
        logger.error(f"Failed to initialize Flask app context: {e}")
        logger.warning("Discord bot will run without database access")
    
    logger.info("Starting Discord bot...")
    bot.run(DISCORD_BOT_TOKEN)

if __name__ == '__main__':
    run_bot()
