def get_custom_css():
    """Return custom CSS for professional styling"""
    return """
    <style>
        .main-header {
            background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin: 0.5rem 0;
        }
        .alert-box {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin: 1rem 0;
            animation: pulse 2s infinite;
        }
        .success-box {
            background: linear-gradient(135deg, #00b894 0%, #00a085 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin: 1rem 0;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.8; }
            100% { opacity: 1; }
        }
        .sidebar .sidebar-content {
            background: linear-gradient(180deg, #2c3e50 0%, #34495e 100%);
        }
    </style>
    """
