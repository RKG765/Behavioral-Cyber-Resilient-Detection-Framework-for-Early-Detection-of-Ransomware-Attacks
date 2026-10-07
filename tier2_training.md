Microsoft Windows [Version 10.0.26200.9457]
(c) Microsoft Corporation. All rights reserved.

D:\project4>python train_tier2.py
=================================================================
  PHASE 1 -- DATA LOADING (exact Tier-1 split)
=================================================================
  Loaded 2,298 sequences from dataset\balanced_training_sequences.json
  X: (2298, 50) torch.int64 | y: (2298, 1) torch.float32
  Train: 1,838 (919 mal + 919 ben)
  Val  : 460 (230 mal + 230 ben)
  [OK] Validation set is IDENTICAL to Tier 1's (X_val, y_val, order)

=================================================================
  PHASE 3 -- TRAINING (Focal Loss, AdamW, Early Stopping)
=================================================================
  Parameters: 59,393  | device: cpu

  Epoch | Train Loss |  Val Loss |  Val Acc |
  ---------------------------------------------
      1 |     0.1178 |    0.1073 |   83.91% | *best
      2 |     0.1082 |    0.1023 |   82.61% | *best
      3 |     0.1045 |    0.0995 |   83.91% | *best
      4 |     0.1032 |    0.0973 |   84.57% | *best
      5 |     0.1018 |    0.0957 |   84.13% | *best
      6 |     0.1002 |    0.0968 |   85.00% |
      7 |     0.1003 |    0.0965 |   84.35% |
      8 |     0.1009 |    0.0968 |   84.57% |
      9 |     0.0982 |    0.0966 |   84.78% |
     10 |     0.0979 |    0.0954 |   85.00% | *best
     11 |     0.0977 |    0.0943 |   85.00% | *best
     12 |     0.0953 |    0.0947 |   85.00% |
     13 |     0.0965 |    0.0955 |   84.13% |
     14 |     0.0957 |    0.0946 |   84.13% |
     15 |     0.0944 |    0.0976 |   84.78% |
     16 |     0.0926 |    0.0946 |   85.00% |

  Early stopping at epoch 16 (best epoch 11, val loss 0.0943)
  Saved best state_dict (epoch 11) -> D:\project4\tier2_cloud_model.pt

=================================================================
  PHASE 4 -- EVALUATION
=================================================================

  [4a] ROC-derived threshold (FPR strictly < 1%)
       AUC = 0.9147
       Selected threshold = 0.6935  (TPR=37.83%, FPR=0.87%)
  ROC-selected (data-driven)         thr=0.6935 | TP= 87 FP=  2 TN=228 FN=143 | TPR= 37.83% FPR= 0.87% Acc= 68.48%
  Fixed reference (0.70)             thr=0.7000 | TP= 57 FP=  0 TN=230 FN=173 | TPR= 24.78% FPR= 0.00% Acc= 62.39%
  Default (0.50)                     thr=0.5000 | TP=193 FP= 32 TN=198 FN= 37 | TPR= 83.91% FPR=13.91% Acc= 85.00%
       NOTE: threshold is selected AND reported on the same validation set
             (no separate test split, because the Tier-1 split is mandatory),
             so these numbers are slightly optimistic.
       Saved -> D:\project4\tier2_threshold.json

  [4b] Tier-1 GREY ZONE evaluation (samples tier1_edr.onnx scored in (0.1, 0.9))
       Tier 1 overall val accuracy @0.50 : 83.70%
       Grey-zone samples: 344 / 460 (173 malware, 171 benign)
       Tier 1 accuracy on grey zone      : 78.20%
  Tier 2 grey zone (ROC thr)         thr=0.6935 | TP= 30 FP=  2 TN=169 FN=143 | TPR= 17.34% FPR= 1.17% Acc= 57.85%
  Tier 2 grey zone (0.70)            thr=0.7000 | TP=  0 FP=  0 TN=171 FN=173 | TPR=  0.00% FPR= 0.00% Acc= 49.71%
  Tier 2 grey zone (0.50)            thr=0.5000 | TP=136 FP= 32 TN=139 FN= 37 | TPR= 78.61% FPR=18.71% Acc= 79.94%
       >>> TIER 2 GREY-ZONE ACCURACY: 57.85%  (vs Tier 1: 78.20%)

  [4c] XAI / ATTENTION sanity check
       Max attention weight on padding positions : 0.0 (13377 padded cells)
       Max |sum(weights) - 1| over all rows      : 1.79e-07
       [OK] Padding gets exactly 0.0 weight; every row sums to 1.

       Known malware sample (val idx 189): Tier-2 p=0.9525, Tier-1 p=0.9977, length=50
       Sequence: [1, 1, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]
       Top-3 Event IDs by attention (weight summed per ID):
         1. EventID  7 (ImageLoad           ) weight=0.9984
         2. EventID  1 (ProcessCreate       ) weight=0.0016
       Weight mass on real events: 1.000000 | on padding: 0.0
       Saved -> D:\project4\tier2_xai_sample.json

  [verify] Reloaded tier2_cloud_model.pt: max |delta p| = 0.00e+00

  DONE.

D:\project4>