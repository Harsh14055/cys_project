#!/usr/bin/env python3
"""
Complete Training and Setup Script for ML-Based Malware Detection System
Run this to generate dataset, train model, and prepare the system
"""

import os
import sys
import argparse
from dataset_generator import create_synthetic_dataset, load_dataset_from_csv
from ml_model_trainer import train_malware_model


def print_banner():
    """Print welcome banner"""
    banner = """
    ╔════════════════════════════════════════════════════════════════╗
    ║     🔐 ML-Based Malware Detection System Setup & Training     ║
    ║     Cybersecurity Project - Semester 6                        ║
    ╚════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main setup and training pipeline"""
    
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Setup and train ML-based malware detection system"
    )
    
    parser.add_argument(
        '--dataset-size',
        type=int,
        default=1000,
        help='Number of samples per class for synthetic dataset (default: 1000)'
    )
    
    parser.add_argument(
        '--model-type',
        choices=['random_forest', 'gradient_boosting'],
        default='random_forest',
        help='Type of ML model to train (default: random_forest)'
    )
    
    parser.add_argument(
        '--skip-dataset',
        action='store_true',
        help='Skip dataset generation if it already exists'
    )
    
    args = parser.parse_args()
    
    print(f"\n📋 Configuration:")
    print(f"   Dataset size: {args.dataset_size} samples per class")
    print(f"   Model type: {args.model_type}")
    print(f"   Skip existing dataset: {args.skip_dataset}")
    
    # Step 1: Generate or load dataset
    dataset_path = 'malware_dataset.csv'
    
    if args.skip_dataset and os.path.exists(dataset_path):
        print(f"\n[*] Using existing dataset: {dataset_path}")
    else:
        print(f"\n{'='*60}")
        print("STEP 1: Generating Synthetic Dataset")
        print(f"{'='*60}")
        create_synthetic_dataset(
            output_path=dataset_path,
            num_samples=args.dataset_size
        )
    
    # Step 2: Train ML model
    print(f"\n{'='*60}")
    print("STEP 2: Training ML Model")
    print(f"{'='*60}")
    
    model_path = 'ml_model.pkl'
    ml_model = train_malware_model(
        dataset_path=dataset_path,
        model_type=args.model_type,
        save_path=model_path
    )
    
    if ml_model is None:
        print("[ERROR] Failed to train model")
        return 1
    
    # Step 3: Print results
    print(f"\n{'='*60}")
    print("✅ SETUP COMPLETE!")
    print(f"{'='*60}")
    
    print(f"\n📊 Model Performance:")
    for metric, value in ml_model.metrics.items():
        print(f"   {metric.replace('_', ' ').title()}: {value:.4f}")
    
    print(f"\n📁 Generated Files:")
    print(f"   ✓ Dataset: {dataset_path}")
    print(f"   ✓ Model: {model_path}")
    
    print(f"\n🚀 Next Steps:")
    print(f"   1. Run the web interface:")
    print(f"      python app.py")
    print(f"\n   2. Or use command-line scanner:")
    print(f"      python scanner_engine.py <file_path>")
    
    print(f"\n💡 Features:")
    print(f"   ✓ Hybrid detection (Signature-based + ML)")
    print(f"   ✓ Web interface on http://localhost:5000")
    print(f"   ✓ Real-time ML predictions")
    print(f"   ✓ Confidence scores")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
