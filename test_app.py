from fastapi import FastAPI

app = FastAPI()

@app.get("/api/cluster/status")
def get_cluster_status():
    return "OK"