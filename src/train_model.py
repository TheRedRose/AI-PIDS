import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

# Load the processed data
data_path = "data/processed/processed_data.csv"
df = pd.read_csv(data_path)

# Strip any leading/trailing spaces from column names
df.columns = df.columns.str.strip()

# Check column names again
print("Columns in dataset after stripping spaces:", df.columns)

# Ensure 'Label' column exists
if 'Label' not in df.columns:
    raise KeyError("Column 'Label' not found in dataset. Check preprocessing step.")

# Convert target labels to categorical if needed
if df['Label'].dtype != 'int':
    print("Converting 'Label' column to categorical class labels...")
    le = LabelEncoder()
    df['Label'] = le.fit_transform(df['Label'])  # Converts labels to 0, 1, 2, ...

# Splitting the data into features and target
X = df.drop(columns=['Label'])  # Features
y = df['Label']  # Target

# Splitting the data into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initializing the XGBoost classifier and training the model
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')
model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Evaluate model performance
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save the model
model.save_model("models/xgboost_model.json")
print("Model saved successfully. Training completed.")
