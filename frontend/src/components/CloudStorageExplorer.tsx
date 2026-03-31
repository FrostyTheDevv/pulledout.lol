import { useState, useEffect } from 'react';
import axios from 'axios';

interface CloudStorageExplorerProps {
  scanId: string;
}

export default function CloudStorageExplorer({ scanId }: CloudStorageExplorerProps) {
  const [cloudData, setCloudData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCloudData();
  }, [scanId]);

  const fetchCloudData = async () => {
    try {
      const response = await axios.get(`/api/tools/${scanId}/cloud-storage-explorer`);
      setCloudData(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch cloud storage data:', error);
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-neutral-800 rounded w-1/4"></div>
          <div className="h-4 bg-neutral-800 rounded"></div>
        </div>
      </div>
    );
  }

  if (!cloudData || !cloudData.exposed) {
    return null;
  }

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  };

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-red-900/20 to-purple-900/20 border-2 border-red-500 rounded-lg p-6">
        <div className="flex items-start space-x-4">
          <div className="flex-shrink-0">
            <div className="w-12 h-12 bg-red-500 rounded-lg flex items-center justify-center">
              <svg className="w-7 h-7 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
              </svg>
            </div>
          </div>
          <div className="flex-1">
            <h3 className="text-2xl font-bold text-red-400 mb-2">
              ☁️ CLOUD STORAGE COMPLETELY EXPOSED
            </h3>
            <p className="text-white text-lg mb-4">
              Your cloud buckets are PUBLIC! Anyone can download ALL your files right now!
            </p>
            <div className="bg-black/50 rounded-lg p-4">
              <p className="text-red-300 font-semibold mb-2">⚠️ CRITICAL DATA BREACH</p>
              <p className="text-gray-300 text-sm">
                The files listed below are ACTUALLY ACCESSIBLE from the internet. Attackers can mass-download your entire storage!
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* AWS S3 Buckets */}
      {cloudData.s3_buckets && cloudData.s3_buckets.length > 0 && (
        <div className="bg-neutral-900 border border-orange-500/50 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-orange-600 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z" />
              </svg>
            </div>
            <div>
              <h4 className="text-xl font-bold text-white">AWS S3 - PUBLIC BUCKETS FOUND</h4>
              <p className="text-sm text-gray-400">{cloudData.s3_buckets.length} exposed bucket(s)</p>
            </div>
          </div>

          {cloudData.s3_buckets.map((bucket: any, idx: number) => (
            <div key={idx} className="mb-6 bg-neutral-950 rounded-lg p-4 border border-neutral-800">
              <div className="flex items-center justify-between mb-4">
                <h5 className="text-lg font-bold text-orange-400">🪣 {bucket.name}</h5>
                <span className="text-sm text-gray-400">{bucket.file_count} files</span>
              </div>

              {bucket.files && bucket.files.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs text-red-400 mb-2">📂 PUBLIC FILES (ANYONE CAN DOWNLOAD):</p>
                  <div className="bg-black rounded-lg p-3 max-h-96 overflow-y-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-neutral-800">
                          <th className="text-left text-gray-400 font-semibold pb-2">File Name</th>
                          <th className="text-right text-gray-400 font-semibold pb-2">Size</th>
                          <th className="text-right text-gray-400 font-semibold pb-2">Last Modified</th>
                        </tr>
                      </thead>
                      <tbody>
                        {bucket.files.map((file: any, fileIdx: number) => (
                          <tr key={fileIdx} className="border-b border-neutral-900">
                            <td className="py-2 text-green-400 font-mono text-xs">{file.key}</td>
                            <td className="py-2 text-right text-gray-400">{formatFileSize(file.size)}</td>
                            <td className="py-2 text-right text-gray-400 text-xs">{file.last_modified}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              <div className="mt-4 bg-red-900/20 border border-red-500 rounded-lg p-4">
                <p className="text-red-300 font-semibold mb-2">💀 MASS DOWNLOAD COMMANDS:</p>
                <div className="bg-black rounded p-3">
                  <pre className="text-green-400 text-xs font-mono">
{`# Install AWS CLI
pip install awscli

# Download ENTIRE bucket (NO credentials needed!)
aws s3 sync s3://${bucket.name} ./stolen_data/${bucket.name}/ --no-sign-request

# Attacker now has ALL your files!`}
                  </pre>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Azure Blob Storage */}
      {cloudData.azure_containers && cloudData.azure_containers.length > 0 && (
        <div className="bg-neutral-900 border border-blue-500/50 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z" />
              </svg>
            </div>
            <div>
              <h4 className="text-xl font-bold text-white">Azure Blob - PUBLIC CONTAINERS</h4>
              <p className="text-sm text-gray-400">{cloudData.azure_containers.length} exposed container(s)</p>
            </div>
          </div>

          {cloudData.azure_containers.map((container: any, idx: number) => (
            <div key={idx} className="mb-6 bg-neutral-950 rounded-lg p-4 border border-neutral-800">
              <div className="flex items-center justify-between mb-4">
                <h5 className="text-lg font-bold text-blue-400">📦 {container.name}</h5>
                <span className="text-sm text-gray-400">{container.blob_count} blobs</span>
              </div>

              {container.blobs && container.blobs.length > 0 && (
                <div className="bg-black rounded-lg p-3 max-h-96 overflow-y-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-neutral-800">
                        <th className="text-left text-gray-400 font-semibold pb-2">Blob Name</th>
                        <th className="text-right text-gray-400 font-semibold pb-2">Size</th>
                      </tr>
                    </thead>
                    <tbody>
                      {container.blobs.map((blob: any, blobIdx: number) => (
                        <tr key={blobIdx} className="border-b border-neutral-900">
                          <td className="py-2 text-green-400 font-mono text-xs">{blob.name}</td>
                          <td className="py-2 text-right text-gray-400">{formatFileSize(blob.size)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="mt-4 bg-red-900/20 border border-red-500 rounded-lg p-4">
                <p className="text-red-300 font-semibold mb-2">⚠️ PUBLIC ACCESS URL:</p>
                <div className="bg-black rounded p-3">
                  <pre className="text-green-400 text-xs font-mono break-all">
{`https://${container.account}.blob.core.windows.net/${container.name}/`}
                  </pre>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Google Cloud Storage */}
      {cloudData.gcs_buckets && cloudData.gcs_buckets.length > 0 && (
        <div className="bg-neutral-900 border border-red-500/50 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-red-600 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                <path d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
              </svg>
            </div>
            <div>
              <h4 className="text-xl font-bold text-white">Google Cloud Storage - PUBLIC BUCKETS</h4>
              <p className="text-sm text-gray-400">{cloudData.gcs_buckets.length} exposed bucket(s)</p>
            </div>
          </div>

          {cloudData.gcs_buckets.map((bucket: any, idx: number) => (
            <div key={idx} className="mb-6 bg-neutral-950 rounded-lg p-4 border border-neutral-800">
              <div className="flex items-center justify-between mb-4">
                <h5 className="text-lg font-bold text-red-400">🗂️ {bucket.name}</h5>
                <span className="text-sm text-gray-400">{bucket.object_count} objects</span>
              </div>

              {bucket.objects && bucket.objects.length > 0 && (
                <div className="bg-black rounded-lg p-3 max-h-96 overflow-y-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-neutral-800">
                        <th className="text-left text-gray-400 font-semibold pb-2">Object Name</th>
                        <th className="text-right text-gray-400 font-semibold pb-2">Size</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bucket.objects.map((obj: any, objIdx: number) => (
                        <tr key={objIdx} className="border-b border-neutral-900">
                          <td className="py-2 text-green-400 font-mono text-xs">{obj.name}</td>
                          <td className="py-2 text-right text-gray-400">{formatFileSize(obj.size)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="mt-4 bg-red-900/20 border border-red-500 rounded-lg p-4">
                <p className="text-red-300 font-semibold mb-2">📥 DOWNLOAD ALL FILES:</p>
                <div className="bg-black rounded p-3">
                  <pre className="text-green-400 text-xs font-mono">
{`# Install gsutil
pip install gsutil

# Download entire bucket (NO auth required!)
gsutil -m cp -r gs://${bucket.name} ./stolen_data/

# All files stolen!`}
                  </pre>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Fix Instructions */}
      <div className="bg-red-900/10 border-2 border-red-500 rounded-lg p-6">
        <h4 className="text-xl font-bold text-red-400 mb-4">🚨 IMMEDIATE FIX REQUIRED</h4>
        <div className="space-y-3 text-white">
          <p className="font-semibold">Your cloud storage is COMPLETELY PUBLIC!</p>
          <ol className="list-decimal list-inside space-y-2 text-sm">
            <li><strong>AWS S3:</strong> Remove public ACLs, Enable "Block All Public Access"</li>
            <li><strong>Azure:</strong> Set container access to "Private", use SAS tokens</li>
            <li><strong>GCS:</strong> Remove allUsers and allAuthenticatedUsers permissions</li>
            <li>Audit all bucket policies and IAM roles immediately</li>
            <li>Enable logging to detect unauthorized access</li>
            <li>Consider all exposed data as COMPROMISED - rotate credentials!</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
