"""
Machine Learning Training Pipeline for AI-Based Network Intrusion Detection System
Uses CICIDS2017 dataset to train multiple classifiers for network attack detection.

Features:
- Data preprocessing and cleaning
- Feature selection and engineering
- Multiple classifier training (Random Forest, Decision Tree, KNN, Logistic Regression)
- Hyperparameter tuning with GridSearchCV
- Model evaluation with comprehensive metrics
- Visualization of results
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                           f1_score, confusion_matrix, classification_report)
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import warnings
import os
from datetime import datetime

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# Set plot style
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")


class NIDSModelTrainer:
    """
    Adds anomaly detection (IsolationForest) for Zero-Day attack detection.
    """
    """
    A comprehensive machine learning pipeline for training network intrusion
    detection models using the CICIDS2017 dataset.
    """
    
    def __init__(self, dataset_path='dataset/CICIDS2017.csv'):
        """
        Initialize the trainer with dataset path.
        
        Args:
            dataset_path (str): Path to the CICIDS2017 CSV file
        """
        self.dataset_path = dataset_path
        self.model_dir = 'model'
        self.df = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.scaler = None
        self.label_encoder = None
        self.best_model = None
        self.feature_names = None
        self.anomaly_model = None
            def train_anomaly_detector(self):
                """
                Train IsolationForest on normal (benign) data for Zero-Day detection.
                """
                print("\n" + "="*60)
                print("🛡 TRAINING ANOMALY DETECTOR (Zero-Day)")
                print("="*60)
                # Only use normal data
                normal_mask = self.df['Label'] == 'Normal'
                X_normal = self.df.loc[normal_mask, self.feature_names].values
                if len(X_normal) < 100:
                    print("  ⚠ Not enough normal samples for anomaly detection. Skipping.")
                    self.anomaly_model = None
                    return
                # Use same scaling as main model
                X_normal_scaled = self.scaler.transform(X_normal)
                self.anomaly_model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
                self.anomaly_model.fit(X_normal_scaled)
                print(f"  ✓ Trained IsolationForest on {len(X_normal)} normal samples.")
        
        # Selected features based on importance and relevance
        self.selected_features = [
            'Flow Duration',
            'Total Fwd Packets',
            'Total Backward Packets',
            'Flow Bytes/s',
            'Flow Packets/s',
            'Packet Length Mean',
            'Packet Length Std',
            'Protocol',
            'Source Port',
            'Destination Port',
            'Fwd Packet Length Mean',
            'Bwd Packet Length Mean',
            'Flow IAT Mean',
            'Fwd IAT Mean',
            'Bwd IAT Mean',
            'Average Packet Size',
            'Avg Fwd Segment Size',
            'Avg Bwd Segment Size'
        ]
        
        # Mapping for attack labels
        self.label_mapping = {
            'BENIGN': 'Normal',
            'DoS Hulk': 'DoS',
            'DoS GoldenEye': 'DoS',
            'DoS slowloris': 'DoS',
            'DoS Slowhttptest': 'DoS',
            'DDoS': 'DoS',
            'FTP-Patator': 'BruteForce',
            'SSH-Patator': 'BruteForce',
            'PortScan': 'PortScan',
            'Bot': 'Botnet',
            'Web Attack – Brute Force': 'WebAttack',
            'Web Attack – XSS': 'WebAttack',
            'Web Attack – Sql Injection': 'WebAttack',
            'Web Attack - Brute Force': 'WebAttack',
            'Web Attack - XSS': 'WebAttack',
            'Web Attack - Sql Injection': 'WebAttack',
            'Infiltration': 'WebAttack',
            'Heartbleed': 'DoS'
        }
        
        # Create model directory
        os.makedirs(self.model_dir, exist_ok=True)
        
    def load_data(self):
        """
        Load the CICIDS2017 dataset from CSV file.
        Handles multiple CSV files if present.
        """
        print("\n" + "="*60)
        print("📊 LOADING DATASET")
        print("="*60)
        
        try:
            # Check if dataset exists
            if os.path.exists(self.dataset_path):
                self.df = pd.read_csv(self.dataset_path, low_memory=False)
            else:
                # Try to load from dataset directory
                dataset_dir = 'dataset'
                csv_files = [f for f in os.listdir(dataset_dir) if f.endswith('.csv')]
                
                if csv_files:
                    dfs = []
                    for csv_file in csv_files:
                        print(f"  Loading: {csv_file}")
                        df_temp = pd.read_csv(os.path.join(dataset_dir, csv_file), low_memory=False)
                        dfs.append(df_temp)
                    self.df = pd.concat(dfs, ignore_index=True)
                else:
                    # Create synthetic dataset for demonstration
                    print("  ⚠ Dataset not found. Creating synthetic dataset...")
                    self.df = self._create_synthetic_dataset()
            
            print(f"\n  ✓ Dataset loaded successfully!")
            print(f"  • Shape: {self.df.shape}")
            print(f"  • Columns: {len(self.df.columns)}")
            print(f"  • Records: {len(self.df):,}")
            
        except Exception as e:
            print(f"  ✗ Error loading dataset: {e}")
            print("  Creating synthetic dataset for demonstration...")
            self.df = self._create_synthetic_dataset()
            
    def _create_synthetic_dataset(self):
        """
        Create a synthetic dataset for demonstration purposes.
        This simulates the CICIDS2017 dataset structure.
        """
        np.random.seed(42)
        n_samples = 50000
        
        # Generate synthetic features
        data = {
            'Flow Duration': np.random.exponential(1000000, n_samples),
            'Total Fwd Packets': np.random.poisson(10, n_samples),
            'Total Backward Packets': np.random.poisson(8, n_samples),
            'Flow Bytes/s': np.random.exponential(50000, n_samples),
            'Flow Packets/s': np.random.exponential(100, n_samples),
            'Packet Length Mean': np.random.exponential(500, n_samples),
            'Packet Length Std': np.random.exponential(300, n_samples),
            'Protocol': np.random.choice([6, 17, 1], n_samples, p=[0.7, 0.25, 0.05]),
            'Source Port': np.random.randint(1024, 65535, n_samples),
            'Destination Port': np.random.choice([80, 443, 22, 21, 25, 53, 3389], n_samples),
            'Fwd Packet Length Mean': np.random.exponential(400, n_samples),
            'Bwd Packet Length Mean': np.random.exponential(600, n_samples),
            'Flow IAT Mean': np.random.exponential(100000, n_samples),
            'Fwd IAT Mean': np.random.exponential(150000, n_samples),
            'Bwd IAT Mean': np.random.exponential(200000, n_samples),
            'Average Packet Size': np.random.exponential(500, n_samples),
            'Avg Fwd Segment Size': np.random.exponential(400, n_samples),
            'Avg Bwd Segment Size': np.random.exponential(600, n_samples)
        }
        
        # Generate labels with realistic distribution
        labels = np.random.choice(
            ['BENIGN', 'DoS Hulk', 'PortScan', 'FTP-Patator', 'Bot', 'Web Attack – XSS'],
            n_samples,
            p=[0.7, 0.1, 0.08, 0.05, 0.04, 0.03]
        )
        
        # Modify features based on attack type to create realistic patterns
        df = pd.DataFrame(data)
        df['Label'] = labels
        
        # DoS attacks have high packet rates
        dos_mask = df['Label'].str.contains('DoS', na=False)
        df.loc[dos_mask, 'Flow Packets/s'] *= 10
        df.loc[dos_mask, 'Total Fwd Packets'] *= 5
        
        # PortScan has many short connections
        portscan_mask = df['Label'] == 'PortScan'
        df.loc[portscan_mask, 'Flow Duration'] /= 10
        df.loc[portscan_mask, 'Destination Port'] = np.random.randint(1, 65535, sum(portscan_mask))
        
        # BruteForce has repetitive patterns
        brute_mask = df['Label'].str.contains('Patator', na=False)
        df.loc[brute_mask, 'Flow Duration'] = np.random.normal(5000, 500, sum(brute_mask))
        
        return df
    
    def preprocess_data(self):
        """
        Preprocess the dataset including cleaning and feature engineering.
        """
        print("\n" + "="*60)
        print("🔧 PREPROCESSING DATA")
        print("="*60)
        
        # Strip whitespace from column names
        self.df.columns = self.df.columns.str.strip()
        
        # Handle Label column
        if ' Label' in self.df.columns:
            self.df.rename(columns={' Label': 'Label'}, inplace=True)
        
        print(f"\n  Initial shape: {self.df.shape}")
        
        # Remove duplicates
        initial_rows = len(self.df)
        self.df.drop_duplicates(inplace=True)
        removed_dups = initial_rows - len(self.df)
        print(f"  • Removed {removed_dups:,} duplicate rows")
        
        # Handle missing values
        missing_before = self.df.isnull().sum().sum()
        self.df.dropna(inplace=True)
        print(f"  • Removed rows with {missing_before} missing values")
        
        # Replace infinite values
        numeric_cols = self.df.select_dtypes(include=[np.number]).columns
        self.df[numeric_cols] = self.df[numeric_cols].replace([np.inf, -np.inf], 0)
        print("  • Replaced infinite values with 0")
        
        # Map labels to attack categories
        self.df['Label'] = self.df['Label'].str.strip()
        self.df['Label'] = self.df['Label'].map(
            lambda x: self.label_mapping.get(x, 'Normal')
        )
        
        print(f"\n  Final shape: {self.df.shape}")
        print(f"\n  Label distribution:")
        label_counts = self.df['Label'].value_counts()
        for label, count in label_counts.items():
            percentage = (count / len(self.df)) * 100
            print(f"    • {label}: {count:,} ({percentage:.1f}%)")
            
    def select_features(self):
        """
        Select relevant features for model training.
        """
        print("\n" + "="*60)
        print("🎯 FEATURE SELECTION")
        print("="*60)
        
        # Get available features
        available_features = [f for f in self.selected_features if f in self.df.columns]
        
        if len(available_features) < 5:
            # Use all numeric columns except Label
            available_features = self.df.select_dtypes(include=[np.number]).columns.tolist()
            if 'Label' in available_features:
                available_features.remove('Label')
        
        self.feature_names = available_features
        
        print(f"\n  Selected {len(self.feature_names)} features:")
        for i, feature in enumerate(self.feature_names, 1):
            print(f"    {i}. {feature}")
        
        # Prepare feature matrix and target
        self.X = self.df[self.feature_names].values
        
        # Encode labels
        self.label_encoder = LabelEncoder()
        self.y = self.label_encoder.fit_transform(self.df['Label'])
        
        print(f"\n  Classes: {list(self.label_encoder.classes_)}")
        
    def split_and_scale(self):
        """
        Split data into training and testing sets, and apply scaling.
        """
        print("\n" + "="*60)
        print("📊 DATA SPLITTING & SCALING")
        print("="*60)
        
        # Stratified split to maintain class distribution
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            self.X, self.y, 
            test_size=0.2, 
            random_state=42,
            stratify=self.y
        )
        
        print(f"\n  Training samples: {len(self.X_train):,}")
        print(f"  Testing samples: {len(self.X_test):,}")
        
        # Apply StandardScaler
        self.scaler = StandardScaler()
        self.X_train = self.scaler.fit_transform(self.X_train)
        self.X_test = self.scaler.transform(self.X_test)
        
        print("  ✓ Data scaled using StandardScaler")
        
        # Save scaler
        scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
        print(f"  ✓ Scaler saved to {scaler_path}")
        
    def train_models(self):
        """
        Train multiple classifiers and compare performance.
        """
        print("\n" + "="*60)
        print("🤖 TRAINING MODELS")
        print("="*60)
        
        models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                random_state=42,
                n_jobs=-1
            ),
            'Decision Tree': DecisionTreeClassifier(
                max_depth=20,
                min_samples_split=5,
                random_state=42
            ),
            'KNN': KNeighborsClassifier(
                n_neighbors=5,
                n_jobs=-1
            ),
            'Logistic Regression': LogisticRegression(
                max_iter=1000,
                random_state=42,
                n_jobs=-1
            )
        }
        
        results = {}
        
        for name, model in models.items():
            print(f"\n  Training {name}...")
            
            # Train model
            model.fit(self.X_train, self.y_train)
            
            # Evaluate
            y_pred = model.predict(self.X_test)
            
            accuracy = accuracy_score(self.y_test, y_pred)
            precision = precision_score(self.y_test, y_pred, average='weighted', zero_division=0)
            recall = recall_score(self.y_test, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(self.y_test, y_pred, average='weighted', zero_division=0)
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'predictions': y_pred
            }
            
            print(f"    ✓ Accuracy: {accuracy*100:.2f}%")
            print(f"    ✓ F1-Score: {f1*100:.2f}%")
        
        self.results = results
        
        # Select best model based on accuracy
        best_name = max(results.keys(), key=lambda x: results[x]['accuracy'])
        self.best_model = results[best_name]['model']
        print(f"\n  🏆 Best Model: {best_name}")
        
    def optimize_random_forest(self):
        """
        Optimize Random Forest using GridSearchCV.
        """
        print("\n" + "="*60)
        print("⚡ HYPERPARAMETER OPTIMIZATION")
        print("="*60)
        
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 20, 30],
            'min_samples_split': [2, 5, 10]
        }
        
        print("\n  Running GridSearchCV...")
        print("  Parameters to search:")
        for param, values in param_grid.items():
            print(f"    • {param}: {values}")
        
        rf = RandomForestClassifier(random_state=42, n_jobs=-1)
        
        # Use smaller subset for faster grid search
        sample_size = min(10000, len(self.X_train))
        indices = np.random.choice(len(self.X_train), sample_size, replace=False)
        X_sample = self.X_train[indices]
        y_sample = self.y_train[indices]
        
        grid_search = GridSearchCV(
            rf, param_grid, 
            cv=3, 
            scoring='accuracy',
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_sample, y_sample)
        
        print(f"\n  ✓ Best parameters: {grid_search.best_params_}")
        print(f"  ✓ Best CV accuracy: {grid_search.best_score_*100:.2f}%")
        
        # Train final model with best parameters
        self.best_model = RandomForestClassifier(
            **grid_search.best_params_,
            random_state=42,
            n_jobs=-1
        )
        self.best_model.fit(self.X_train, self.y_train)
        
        # Final evaluation
        y_pred = self.best_model.predict(self.X_test)
        final_accuracy = accuracy_score(self.y_test, y_pred)
        print(f"  ✓ Final test accuracy: {final_accuracy*100:.2f}%")
        
    def evaluate_model(self):
        """
        Comprehensive model evaluation with detailed metrics.
        """
        print("\n" + "="*60)
        print("📈 MODEL EVALUATION")
        print("="*60)
        
        y_pred = self.best_model.predict(self.X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(self.y_test, y_pred)
        precision = precision_score(self.y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(self.y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(self.y_test, y_pred, average='weighted', zero_division=0)
        
        print(f"\n  ╔{'═'*40}╗")
        print(f"  ║{'FINAL RESULTS':^40}║")
        print(f"  ╠{'═'*40}╣")
        print(f"  ║ Accuracy:  {accuracy*100:>26.2f}% ║")
        print(f"  ║ Precision: {precision*100:>26.2f}% ║")
        print(f"  ║ Recall:    {recall*100:>26.2f}% ║")
        print(f"  ║ F1-Score:  {f1*100:>26.2f}% ║")
        print(f"  ╚{'═'*40}╝")
        
        # Classification Report
        print("\n  Classification Report:")
        print("-" * 60)
        report = classification_report(
            self.y_test, y_pred,
            target_names=self.label_encoder.classes_,
            zero_division=0
        )
        for line in report.split('\n'):
            print(f"  {line}")
        
        # Store metrics
        self.metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
        
        # Confusion matrix
        self.cm = confusion_matrix(self.y_test, y_pred)
        
    def plot_results(self):
        """
        Create visualization plots for model performance.
        """
        print("\n" + "="*60)
        print("📊 GENERATING VISUALIZATIONS")
        print("="*60)
        
        # Create figure with subplots
        fig = plt.figure(figsize=(16, 12))
        fig.suptitle('AI-Based Network Intrusion Detection System\nModel Performance Analysis', 
                     fontsize=14, fontweight='bold', y=1.02)
        
        # 1. Confusion Matrix
        ax1 = fig.add_subplot(2, 2, 1)
        sns.heatmap(
            self.cm, 
            annot=True, 
            fmt='d', 
            cmap='Blues',
            xticklabels=self.label_encoder.classes_,
            yticklabels=self.label_encoder.classes_,
            ax=ax1
        )
        ax1.set_title('Confusion Matrix', fontweight='bold')
        ax1.set_xlabel('Predicted Label')
        ax1.set_ylabel('True Label')
        
        # 2. Feature Importance
        ax2 = fig.add_subplot(2, 2, 2)
        if hasattr(self.best_model, 'feature_importances_'):
            importances = self.best_model.feature_importances_
            indices = np.argsort(importances)[::-1][:15]  # Top 15 features
            
            colors = plt.cm.RdYlGn(np.linspace(0.2, 0.8, len(indices)))
            ax2.barh(range(len(indices)), importances[indices], color=colors)
            ax2.set_yticks(range(len(indices)))
            ax2.set_yticklabels([self.feature_names[i] for i in indices])
            ax2.invert_yaxis()
            ax2.set_title('Feature Importance (Top 15)', fontweight='bold')
            ax2.set_xlabel('Importance Score')
        
        # 3. Model Comparison
        ax3 = fig.add_subplot(2, 2, 3)
        if hasattr(self, 'results'):
            models = list(self.results.keys())
            accuracies = [self.results[m]['accuracy'] * 100 for m in models]
            
            bars = ax3.bar(models, accuracies, color=['#3498db', '#2ecc71', '#e74c3c', '#9b59b6'])
            ax3.set_ylabel('Accuracy (%)')
            ax3.set_title('Model Accuracy Comparison', fontweight='bold')
            ax3.set_ylim([min(accuracies) - 5, 100])
            
            # Add value labels
            for bar, acc in zip(bars, accuracies):
                ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                        f'{acc:.1f}%', ha='center', va='bottom', fontweight='bold')
        
        # 4. Class Distribution
        ax4 = fig.add_subplot(2, 2, 4)
        labels = self.label_encoder.classes_
        sizes = [np.sum(self.y == i) for i in range(len(labels))]
        colors = ['#27ae60', '#e74c3c', '#f39c12', '#3498db', '#9b59b6', '#1abc9c']
        explode = [0.05] * len(labels)
        
        ax4.pie(sizes, explode=explode, labels=labels, colors=colors[:len(labels)],
               autopct='%1.1f%%', shadow=True, startangle=90)
        ax4.set_title('Attack Type Distribution', fontweight='bold')
        
        plt.tight_layout()
        
        # Save plot
        plot_path = os.path.join(self.model_dir, 'model_performance.png')
        plt.savefig(plot_path, dpi=150, bbox_inches='tight', facecolor='white')
        print(f"  ✓ Saved performance plot to {plot_path}")
        
        # Show plot
        plt.show()
        
    def save_model(self):
        """
        Save the trained model and related artifacts.
        """
        print("\n" + "="*60)
        print("💾 SAVING MODEL")
        print("="*60)
        
        # Save model
        model_path = os.path.join(self.model_dir, 'model.pkl')
        joblib.dump(self.best_model, model_path)
        print(f"  ✓ Model saved to {model_path}")

        # Save anomaly model
        if self.anomaly_model is not None:
            anomaly_path = os.path.join(self.model_dir, 'anomaly_model.pkl')
            joblib.dump(self.anomaly_model, anomaly_path)
            print(f"  ✓ Anomaly detector saved to {anomaly_path}")
        
        # Save label encoder
        encoder_path = os.path.join(self.model_dir, 'label_encoder.pkl')
        joblib.dump(self.label_encoder, encoder_path)
        print(f"  ✓ Label encoder saved to {encoder_path}")
        
        # Save feature names
        features_path = os.path.join(self.model_dir, 'features.pkl')
        joblib.dump(self.feature_names, features_path)
        print(f"  ✓ Feature names saved to {features_path}")
        
        # Save model metadata
        metadata = {
            'trained_at': datetime.now().isoformat(),
            'accuracy': self.metrics['accuracy'],
            'precision': self.metrics['precision'],
            'recall': self.metrics['recall'],
            'f1': self.metrics['f1'],
            'n_features': len(self.feature_names),
            'n_classes': len(self.label_encoder.classes_),
            'classes': list(self.label_encoder.classes_),
            'feature_names': self.feature_names
        }
        metadata_path = os.path.join(self.model_dir, 'model_metadata.pkl')
        joblib.dump(metadata, metadata_path)
        print(f"  ✓ Metadata saved to {metadata_path}")
        
    def run_pipeline(self):
        """
        Execute the complete training pipeline.
        """
        print("\n" + "#"*60)
        print("#" + " "*58 + "#")
        print("#   AI-BASED NETWORK INTRUSION DETECTION SYSTEM   #")
        print("#         Machine Learning Training Pipeline          #")
        print("#" + " "*58 + "#")
        print("#"*60)
        
        start_time = datetime.now()
        
        # Execute pipeline steps
        self.load_data()
        self.preprocess_data()
        self.select_features()
        self.split_and_scale()
        self.train_models()
        self.optimize_random_forest()
        self.evaluate_model()
        self.plot_results()
        self.train_anomaly_detector()
        self.save_model()
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print("\n" + "="*60)
        print("✅ TRAINING COMPLETE")
        print("="*60)
        print(f"\n  Total time: {duration:.2f} seconds")
        print(f"  Final accuracy: {self.metrics['accuracy']*100:.2f}%")
        print("\n  Model artifacts saved in 'model/' directory:")
        print("    • model.pkl - Trained classifier")
        print("    • scaler.pkl - Feature scaler")
        print("    • label_encoder.pkl - Label encoder")
        print("    • features.pkl - Feature names")
        print("    • model_metadata.pkl - Training metadata")
        print("    • model_performance.png - Performance visualization")
        print("\n" + "="*60)


def predict_single(features, model_dir='model'):
    """
    Make a prediction for a single sample.
    
    Args:
        features (list/array): Feature values for prediction
        model_dir (str): Directory containing model files
        
    Returns:
        tuple: (predicted_label, confidence, all_probabilities)
    """
    # Load model artifacts
    model = joblib.load(os.path.join(model_dir, 'model.pkl'))
    scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
    label_encoder = joblib.load(os.path.join(model_dir, 'label_encoder.pkl'))
    
    # Preprocess
    features = np.array(features).reshape(1, -1)
    features_scaled = scaler.transform(features)
    
    # Predict
    prediction = model.predict(features_scaled)[0]
    probabilities = model.predict_proba(features_scaled)[0]
    
    label = label_encoder.inverse_transform([prediction])[0]
    confidence = float(np.max(probabilities))
    
    return label, confidence, dict(zip(label_encoder.classes_, probabilities))


if __name__ == "__main__":
    # Run the training pipeline
    trainer = NIDSModelTrainer()
    trainer.run_pipeline()
