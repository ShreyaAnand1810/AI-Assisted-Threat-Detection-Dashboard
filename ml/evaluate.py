from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

"""
Evaluation module for ML Threat Detection Pipeline.
Calculates performance metrics for trained classifiers on test datasets.
"""

def evaluate_model(model, X_test, y_test):
    """
    Evaluates trained model performance on test dataset and prints formatted metrics.
    
    Returns:
        dict: Summary dictionary containing calculated metrics.
    """
    y_pred = model.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, zero_division=0)
    
    print("=" * 40)
    print("      MODEL EVALUATION RESULTS      ")
    print("=" * 40)
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print("-" * 40)
    print("Confusion Matrix:")
    print(cm)
    print("-" * 40)
    print("Classification Report:")
    print(report)
    print("=" * 40)
    
    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "confusion_matrix": cm,
        "classification_report": report
    }
