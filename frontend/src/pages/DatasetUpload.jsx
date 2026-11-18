import React, { useState } from 'react';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, Play, Database } from 'lucide-react';
import axios from 'axios';

export default function DatasetUpload({ onAnalysisTriggered, isAnalyzing }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState(null); // 'idle' | 'uploading' | 'success' | 'error'
  const [uploadResult, setUploadResult] = useState(null);
  const [sampleSize, setSampleSize] = useState(50);
  const [errorMessage, setErrorMessage] = useState('');

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (!file.name.toLowerCase().endsWith('.csv')) {
        setErrorMessage('Invalid file type. Please select a CSV (.csv) network telemetry file.');
        return;
      }
      if (file.size > 50 * 1024 * 1024) {
        setErrorMessage('File size exceeds the 50 MB limit.');
        return;
      }
      setSelectedFile(file);
      setErrorMessage('');
      setUploadStatus('idle');
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setUploadStatus('uploading');
    setErrorMessage('');

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const res = await axios.post('/api/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setUploadResult(res.data);
      setUploadStatus('success');
    } catch (err) {
      setUploadStatus('error');
      setErrorMessage(err.response?.data?.detail || 'Failed to upload dataset.');
    }
  };

  const handleRunAnalysis = (fileId) => {
    onAnalysisTriggered({ file_id: fileId, sample_size: sampleSize });
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Intro Header */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow">
        <h2 className="text-base font-bold text-[#f4eded]">Network Telemetry Ingestion Gateway</h2>
        <p className="text-xs text-[#f4eded]/70 mt-1">
          Upload raw or pre-filtered network flow CSV records (CICIDS2017 schema). The Data Processing Agent will
          automatically isolate metadata (IPs, ports, timestamps) and extract 65 model-invariant flow features.
        </p>
      </div>

      {/* Upload Zone */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-6 shadow">
        <div className="border-2 border-dashed border-[#f4eded]/20 hover:border-[#ff6b5b] transition-colors rounded-xl p-8 text-center flex flex-col items-center justify-center">
          <UploadCloud className="w-12 h-12 text-[#ff6b5b] mb-3" />
          <h3 className="text-sm font-bold text-[#f4eded]">Drag and drop your network flow CSV</h3>
          <p className="text-xs text-[#f4eded]/60 mt-1 mb-4">Supported format: CSV (Max: 50 MB)</p>

          <label className="cursor-pointer px-4 py-2 rounded-lg text-xs font-semibold bg-[#ff6b5b] text-[#14213d] hover:bg-[#ff5340] transition-colors shadow-md">
            <span>Browse Local File</span>
            <input type="file" accept=".csv" onChange={handleFileChange} className="hidden" />
          </label>

          {selectedFile && (
            <div className="mt-4 flex items-center gap-2 text-xs font-mono text-[#f4eded] bg-[#14213d] border border-[#f4eded]/20 px-3 py-1.5 rounded-lg">
              <FileText className="w-4 h-4 text-[#ff6b5b]" />
              <span>{selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)</span>
            </div>
          )}
        </div>

        {errorMessage && (
          <div className="mt-4 p-3 rounded-lg bg-[#ff6b5b]/10 border border-[#ff6b5b] text-[#ff6b5b] text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Upload Action */}
        {selectedFile && uploadStatus !== 'success' && (
          <div className="mt-4 flex justify-end">
            <button
              onClick={handleUpload}
              disabled={uploadStatus === 'uploading'}
              className="px-5 py-2 rounded-lg text-xs font-semibold bg-[#ff6b5b] text-[#14213d] hover:bg-[#ff5340] disabled:opacity-50 transition-colors shadow"
            >
              {uploadStatus === 'uploading' ? 'Validating & Uploading...' : 'Upload & Validate CSV'}
            </button>
          </div>
        )}

        {/* Success Card */}
        {uploadStatus === 'success' && uploadResult && (
          <div className="mt-4 p-4 rounded-lg bg-[#14213d] border border-[#f4eded]/30 text-xs space-y-2">
            <div className="flex items-center gap-2 text-[#f4eded] font-bold">
              <CheckCircle2 className="w-4 h-4 text-[#ff6b5b]" />
              <span>File Validated Successfully!</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[#f4eded]/80 font-mono text-[11px] pt-1">
              <div>File ID: {uploadResult.file_id}</div>
              <div>Total Rows: {uploadResult.total_rows}</div>
              <div>Columns: {uploadResult.columns.length}</div>
              <div>Size: {(uploadResult.file_size_bytes / 1024).toFixed(1)} KB</div>
            </div>

            <div className="pt-3 border-t border-[#f4eded]/15 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-xs text-[#f4eded]/70">Sample Size to Analyze:</span>
                <input
                  type="number"
                  min="5"
                  max="500"
                  value={sampleSize}
                  onChange={(e) => setSampleSize(Number(e.target.value))}
                  className="w-20 px-2 py-1 rounded bg-[#14213d] border border-[#f4eded]/30 text-xs text-[#f4eded] font-mono"
                />
              </div>

              <button
                onClick={() => handleRunAnalysis(uploadResult.file_id)}
                disabled={isAnalyzing}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#ff6b5b] text-[#14213d] hover:bg-[#ff5340] disabled:opacity-50 transition-colors flex items-center gap-1.5 shadow"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Launch Swarm Investigation</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Alternative: Instant Dev Sample Quick Load */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-bold text-[#f4eded] flex items-center gap-2">
            <Database className="w-4 h-4 text-[#ff6b5b]" />
            <span>Use Benchmark CICIDS2017 Dataset</span>
          </h3>
          <p className="text-xs text-[#f4eded]/70 mt-0.5">
            Instantly run the multi-agent swarm against genuine held-out network flows without uploading a file.
          </p>
        </div>

        <button
          onClick={() => handleRunAnalysis('dev_sample')}
          disabled={isAnalyzing}
          className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#14213d] border border-[#ff6b5b] text-[#ff6b5b] hover:bg-[#ff6b5b] hover:text-[#14213d] transition-all flex items-center gap-2 shadow"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>Analyze 50 Benchmark Flows</span>
        </button>
      </div>
    </div>
  );
}
