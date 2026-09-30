import React, { useState, useEffect } from "react"
import {
  BrainCircuit,
  RotateCw,
  CheckCircle2,
  AlertCircle,
  Database,
  Sliders,
  Award,
  Layers,
  BarChart2
} from "lucide-react"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid
} from "recharts"
import { ModelMetadata } from "../types"
import { fetchModelEvaluation, triggerTrainModel } from "../services/api"

export const ModelPage: React.FC = () => {
  const [model, setModel] = useState<ModelMetadata | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [training, setTraining] = useState<boolean>(false)
  const [trainMessage, setTrainMessage] = useState<string | null>(null)

  const loadMetadata = () => {
    setLoading(true)
    fetchModelEvaluation()
      .then((data) => setModel(data))
      .catch((err) => console.error("Error loading model metadata:", err))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadMetadata()
  }, [])

  const handleRetrain = async () => {
    setTraining(true)
    setTrainMessage(null)
    try {
      const res = await triggerTrainModel()
      setModel(res.metadata)
      setTrainMessage(`Model retrained successfully! Accuracy: ${(res.metadata.accuracy * 100).toFixed(2)}%`)
    } catch (err: any) {
      setTrainMessage(`Training error: ${err.message}`)
    } finally {
      setTraining(false)
    }
  }

  const topFeaturesData = model?.top_features
    ? model.top_features.map((f) => ({
        name: f.display_name.replace(" (sec)", "").replace(" (chars)", "").replace(" (bytes)", ""),
        importance: f.importance
      }))
    : []

  return (
    <div className="space-y-6 p-6">
      {/* Top Banner with Retrain Button */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <div>
          <h1 className="text-base font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <BrainCircuit className="w-5 h-5 text-cyan-400" />
            Machine Learning Architecture & Evaluation
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Supervised Random Forest Classifier + Unsupervised Isolation Forest Anomaly Engine
          </p>
        </div>

        <button
          onClick={handleRetrain}
          disabled={training}
          className="flex items-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs px-4 py-2.5 rounded-lg shadow-lg shadow-cyan-500/20 active:scale-95 disabled:opacity-60 transition-all cursor-pointer"
        >
          <RotateCw className={`w-4 h-4 ${training ? "animate-spin" : ""}`} />
          {training ? "TRAINING IN PROGRESS..." : "RETRAIN MODEL"}
        </button>
      </div>

      {trainMessage && (
        <div className="p-4 bg-cyan-950/60 border border-cyan-800 rounded-xl text-xs font-mono text-cyan-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{trainMessage}</span>
        </div>
      )}

      {loading && !model && (
        <div className="text-center py-16 text-cyan-400 font-mono text-sm animate-pulse">
          Loading ML architecture parameters & evaluation metrics...
        </div>
      )}

      {model && (
        <>
          {/* Key Evaluation Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
              <span className="text-[11px] font-semibold text-slate-400 uppercase">Test Accuracy</span>
              <div className="text-2xl font-extrabold text-emerald-400 mt-2 font-mono">
                {(model.accuracy * 100).toFixed(2)}%
              </div>
              <div className="text-[10px] text-slate-500 mt-1">Stratified 30% Holdout</div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
              <span className="text-[11px] font-semibold text-slate-400 uppercase">F1-Score</span>
              <div className="text-2xl font-extrabold text-cyan-400 mt-2 font-mono">
                {model.f1_score.toFixed(4)}
              </div>
              <div className="text-[10px] text-slate-500 mt-1">Weighted Average</div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
              <span className="text-[11px] font-semibold text-slate-400 uppercase">Precision</span>
              <div className="text-2xl font-extrabold text-white mt-2 font-mono">
                {(model.precision * 100).toFixed(2)}%
              </div>
              <div className="text-[10px] text-slate-500 mt-1">True Positive Ratio</div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
              <span className="text-[11px] font-semibold text-slate-400 uppercase">Recall</span>
              <div className="text-2xl font-extrabold text-white mt-2 font-mono">
                {(model.recall * 100).toFixed(2)}%
              </div>
              <div className="text-[10px] text-slate-500 mt-1">Coverage Rate</div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
              <span className="text-[11px] font-semibold text-slate-400 uppercase">False Positive Rate</span>
              <div className="text-2xl font-extrabold text-emerald-400 mt-2 font-mono">
                {(model.false_positive_rate * 100).toFixed(2)}%
              </div>
              <div className="text-[10px] text-slate-500 mt-1">Normal Misclassified</div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-lg backdrop-blur">
              <span className="text-[11px] font-semibold text-slate-400 uppercase">Input Dimension</span>
              <div className="text-2xl font-extrabold text-purple-400 mt-2 font-mono">
                {model.feature_count}
              </div>
              <div className="text-[10px] text-slate-500 mt-1">Extracted Features</div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Feature Importance Ranking Chart (7 cols) */}
            <div className="lg:col-span-7 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <BarChart2 className="w-4 h-4 text-cyan-400" />
                    Top Discriminating Feature Weights
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Gini impurity reduction across all 100 decision trees
                  </p>
                </div>
              </div>

              <div className="h-80 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={topFeaturesData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis type="number" stroke="#64748b" tick={{ fontSize: 11 }} />
                    <YAxis dataKey="name" type="category" stroke="#94a3b8" tick={{ fontSize: 11 }} width={140} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#0b1120",
                        borderColor: "#334155",
                        borderRadius: "8px",
                        color: "#f8fafc",
                        fontSize: "12px"
                      }}
                    />
                    <Bar dataKey="importance" fill="#06b6d4" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Model Architecture Info (5 cols) */}
            <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                Detector Pipeline Specifications
              </h2>

              <div className="space-y-3 text-xs">
                <div className="bg-slate-950/70 p-3 rounded-xl border border-slate-800 font-mono">
                  <div className="text-slate-500 uppercase text-[10px]">Supervised Classifier</div>
                  <div className="text-white font-bold mt-1">RandomForestClassifier</div>
                  <div className="text-slate-400 text-[11px] mt-0.5">100 Trees, max_depth=12, min_samples=4</div>
                </div>

                <div className="bg-slate-950/70 p-3 rounded-xl border border-slate-800 font-mono">
                  <div className="text-slate-500 uppercase text-[10px]">Anomaly Detection Model</div>
                  <div className="text-white font-bold mt-1">IsolationForest (Unsupervised)</div>
                  <div className="text-slate-400 text-[11px] mt-0.5">100 Trees, contamination=0.15 for Zero-Days</div>
                </div>

                <div className="bg-slate-950/70 p-3 rounded-xl border border-slate-800 font-mono">
                  <div className="text-slate-500 uppercase text-[10px]">Training Dataset Source</div>
                  <div className="text-cyan-300 font-bold mt-1">{model.dataset_name}</div>
                  <div className="text-slate-400 text-[11px] mt-0.5">{model.sample_count} training samples (Synthetic Benchmark)</div>
                </div>

                <div className="bg-slate-950/70 p-3 rounded-xl border border-slate-800 font-mono">
                  <div className="text-slate-500 uppercase text-[10px]">Recognized Threat Classes</div>
                  <div className="flex flex-wrap gap-1 mt-1.5 font-sans">
                    {model.classes.map((cls, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] border border-slate-700">
                        {cls}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Confusion Matrix Table */}
          {model.confusion_matrix && model.confusion_matrix.length > 0 && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
                <Database className="w-4 h-4 text-cyan-400" />
                Holdout Test Set Confusion Matrix
              </h2>
              <div className="overflow-x-auto">
                <table className="w-full text-center text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2.5 px-3 text-left">Actual \ Predicted</th>
                      {model.classes.map((c, i) => (
                        <th key={i} className="py-2.5 px-2 font-mono text-[11px] truncate max-w-[100px]">
                          {c.split(" ")[0]}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                    {model.confusion_matrix.map((row, rIdx) => (
                      <tr key={rIdx} className="hover:bg-slate-800/40">
                        <td className="py-2.5 px-3 text-left font-semibold text-slate-200">
                          {model.classes[rIdx]}
                        </td>
                        {row.map((val, cIdx) => (
                          <td
                            key={cIdx}
                            className={`py-2.5 px-2 font-bold ${
                              rIdx === cIdx
                                ? val > 0 ? "bg-emerald-950/60 text-emerald-400" : "text-slate-500"
                                : val > 0 ? "bg-rose-950/60 text-rose-400" : "text-slate-600"
                            }`}
                          >
                            {val}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
