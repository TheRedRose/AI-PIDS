import os
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

def load_data(folder_path):
    all_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith('.csv')]
    if not all_files:
        raise ValueError("No CSV files found in the dataset folder.")
    
    df_list = [pd.read_csv(file) for file in all_files]
    df = pd.concat(df_list, ignore_index=True)
    print(f"Dataset Loaded: {df.shape[0]} rows, {df.shape[1]} columns from {len(all_files)} files")
    return df

def clean_data(df):
    df.dropna(inplace=True)
    df = df.loc[:, (df != 0).any(axis=0)]  # Remove columns with only zeros
    print("Data cleaned successfully.")
    return df

def encode_categorical(df):
    label_encoders = {}
    for col in df.select_dtypes(include=['object']).columns:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        label_encoders[col] = le
    print("Categorical features encoded successfully.")
    return df, label_encoders

def scale_features(df):
    feature_columns = df.columns[df.columns != 'Label']  # Assuming 'Label' is the target column

    # Convert all columns to numeric, coercing errors (for unexpected non-numeric values)
    df[feature_columns] = df[feature_columns].apply(pd.to_numeric, errors='coerce')

    # Replace inf/-inf with NaN
    df.replace([float("inf"), float("-inf")], pd.NA, inplace=True)

    # Drop rows with NaN values that result from infinite values or type coercion
    df.dropna(inplace=True)

    scaler = StandardScaler()
    df[feature_columns] = scaler.fit_transform(df[feature_columns])

    print("Features scaled successfully.")
    return df


if __name__ == "__main__":
    folder_path = "data/raw/MachineLearningCVE"  # Change this to your dataset path
    df = load_data(folder_path)
    df = clean_data(df)
    df, label_encoders = encode_categorical(df)
    df = scale_features(df)
    df.to_csv("data/processed/processed_data.csv", index=False)
    print("Preprocessing completed. Processed data saved.")
