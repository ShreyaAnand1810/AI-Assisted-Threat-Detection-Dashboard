from datetime import datetime
import random

def get_dashboard_stats():

    return {
        "total_scans": random.randint(500, 1500),
        "threats": random.randint(50, 300),
        "safe": random.randint(200, 1200),
        "accuracy": 98.7,
        "last_scan": datetime.now().strftime("%d-%m-%Y %H:%M")
    }