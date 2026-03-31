import { useState, useEffect } from 'react';
import { getDebugLogs } from '../utils/api';
import toast from 'react-hot-toast';

interface LogEntry {
  timestamp: string;
  level: string;
  category: string;
  message: string;
  details: Record<string, any>;
}

interface DebugStats {
  total: number;
  by_level: Record<string, number>;
  by_category: Record<string, number>;
  recent_errors: Array<{
    timestamp: string;
    category: string;
    message: string;
  }>;
}

export default function DebugPanel() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [stats, setStats] = useState<DebugStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('');
  const [levelFilter, setLevelFilter] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const loadLogs = async () => {
    try {
      const params: any = { limit: 100 };
      if (levelFilter) params.level = levelFilter;
      if (categoryFilter) params.category = categoryFilter;
      
      const data = await getDebugLogs(params);
      setLogs(data.logs || []);
      setStats(data.stats || null);
    } catch (error: any) {
      toast.error(`Failed to load logs: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, [levelFilter, categoryFilter]);

  useEffect(() => {
    if (!autoRefresh) return;
    
    const interval = setInterval(() => {
      loadLogs();
    }, 5000); // Refresh every 5 seconds
    
    return () => clearInterval(interval);
  }, [autoRefresh, levelFilter, categoryFilter]);

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'text-red-600 bg-red-100 border-red-300';
      case 'ERROR':
        return 'text-red-500 bg-red-50 border-red-200';
      case 'WARNING':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'INFO':
        return 'text-blue-500 bg-blue-50 border-blue-200';
      case 'DEBUG':
        return 'text-gray-500 bg-gray-50 border-gray-200';
      default:
        return 'text-gray-600 bg-gray-100 border-gray-300';
    }
  };

  const filteredLogs = logs.filter(log => {
    if (!filter) return true;
    const searchLower = filter.toLowerCase();
    return (
      log.message.toLowerCase().includes(searchLower) ||
      log.category.toLowerCase().includes(searchLower) ||
      JSON.stringify(log.details).toLowerCase().includes(searchLower)
    );
  });

  if (loading) {
    return (
      <div className="text-center py-8">
        <div className="text-gray-400">Loading debug logs...</div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header with Stats */}
      <div className="bg-neutral-950 border border-neutral-800 rounded-lg p-4">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-white">System Debug Logs</h2>
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-2 text-sm text-gray-400">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="rounded"
              />
              Auto-refresh
            </label>
            <button
              onClick={loadLogs}
              className="px-3 py-1 bg-neutral-800 hover:bg-neutral-700 text-white rounded text-sm"
            >
              Refresh
            </button>
          </div>
        </div>

        {/* Stats Grid */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
            <div className="bg-neutral-900 border border-neutral-800 rounded p-3 text-center">
              <div className="text-2xl font-bold text-white">{stats.total}</div>
              <div className="text-xs text-gray-400">Total Logs</div>
            </div>
            {Object.entries(stats.by_level).map(([level, count]) => (
              <div key={level} className="bg-neutral-900 border border-neutral-800 rounded p-3 text-center">
                <div className="text-2xl font-bold text-white">{count}</div>
                <div className={`text-xs ${getLevelColor(level).split(' ')[0]}`}>{level}</div>
              </div>
            ))}
          </div>
        )}

        {/* Filters */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input
            type="text"
            placeholder="Search logs..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-white placeholder-gray-500 text-sm"
          />
          <select
            aria-label="Filter by log level"
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-white text-sm"
          >
            <option value="">All Levels</option>
            <option value="CRITICAL">Critical</option>
            <option value="ERROR">Error</option>
            <option value="WARNING">Warning</option>
            <option value="INFO">Info</option>
            <option value="DEBUG">Debug</option>
          </select>
          <select
            aria-label="Filter by category"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-white text-sm"
          >
            <option value="">All Categories</option>
            <option value="AUTH">Authentication</option>
            <option value="SCAN">Scanning</option>
            <option value="DATABASE">Database</option>
            <option value="API">API</option>
          </select>
        </div>
      </div>

      {/* Logs List */}
      <div className="bg-neutral-950 border border-neutral-800 rounded-lg divide-y divide-neutral-800 max-h-[600px] overflow-y-auto">
        {filteredLogs.length === 0 ? (
          <div className="p-8 text-center text-gray-400">
            No logs found matching filters
          </div>
        ) : (
          filteredLogs.map((log, index) => (
            <div key={index} className="p-4 hover:bg-neutral-900 transition">
              <div className="flex items-start gap-3">
                <span className={`px-2 py-1 rounded text-xs font-medium border ${getLevelColor(log.level)}`}>
                  {log.level}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs text-gray-500">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                    <span className="px-2 py-0.5 bg-neutral-800 text-gray-300 rounded text-xs">
                      {log.category}
                    </span>
                  </div>
                  <div className="text-white text-sm mb-2">{log.message}</div>
                  {Object.keys(log.details).length > 0 && (
                    <details className="text-xs">
                      <summary className="text-gray-400 cursor-pointer hover:text-gray-300">
                        Show details ({Object.keys(log.details).length} fields)
                      </summary>
                      <pre className="mt-2 p-2 bg-black rounded overflow-x-auto text-gray-300">
                        {JSON.stringify(log.details, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
