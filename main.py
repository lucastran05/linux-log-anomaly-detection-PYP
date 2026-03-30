"""
Main pipeline:
auth.log -> parse -> feature -> ML -> alert
"""

from alert import AlertManager

class LogPipeline:
    def __init__(self):
        self.alert = AlertManager()
    
    def run(self):
        print("[*] Starting detection ...")


if __name__ == "__main__":
    pipeline = LogPipeline()
    pipeline.run()

    