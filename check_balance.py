import os
import glob
import pandas as pd

DATASET_ROOT = "dataset"
CANDIDATE_LABEL_COLS = ["label", "class", "is_malware", "malicious", "target", "category", "tag"]

def find_label_column(columns):
    for col in columns:
        if col.lower().strip() in CANDIDATE_LABEL_COLS:
            return col
    # Fallback: check substring match
    for col in columns:
        for candidate in CANDIDATE_LABEL_COLS:
            if candidate in col.lower():
                return col
    return None

def analyze_csv(file_path):
    print(f"\n--- Checking File: {os.path.basename(file_path)} ---")
    try:
        # Read header only first
        preview = pd.read_csv(file_path, nrows=10)
        label_col = find_label_column(preview.columns)
        
        if not label_col:
            print(f"[!] Could not auto-detect label column. Columns available:")
            print(preview.columns.tolist()[:10], "... (total", len(preview.columns), "columns)")
            return

        print(f"Detected Label Column: '{label_col}'")
        
        # Read in chunks to prevent RAM overflow on large CSVs
        chunk_size = 100_000
        counts = pd.Series(dtype=int)
        
        for chunk in pd.read_csv(file_path, usecols=[label_col], chunksize=chunk_size, low_memory=False):
            counts = counts.add(chunk[label_col].value_counts(), fill_value=0)
            
        counts = counts.astype(int)
        total = counts.sum()
        
        print(f"Total Rows: {total:,}")
        for cls, count in counts.items():
            pct = (count / total) * 100
            print(f"  Class '{cls}': {count:,} ({pct:.2f}%)")

    except Exception as e:
        print(f"[Error reading {file_path}]: {e}")

def main():
    if not os.path.exists(DATASET_ROOT):
        print(f"Folder '{DATASET_ROOT}' not found. Make sure you run this from 'project4'.")
        return

    subfolders = [f for f in os.listdir(DATASET_ROOT) if os.path.isdir(os.path.join(DATASET_ROOT, f))]
    
    if not subfolders:
        print("No subfolders found inside 'dataset'.")
        return

    for folder in subfolders:
        folder_path = os.path.join(DATASET_ROOT, folder)
        print("=" * 60)
        print(f"FOLDER: {folder}")
        print("=" * 60)
        
        csv_files = glob.glob(os.path.join(folder_path, "**", "*.csv"), recursive=True)
        
        if not csv_files:
            print("No CSV files found in this folder.")
            continue
            
        for csv_file in csv_files:
            analyze_csv(csv_file)

if __name__ == "__main__":
    main()