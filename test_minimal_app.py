from fastapi import FastAPI

app = FastAPI(
    title="Test App",
    description="Test application",
    version="0.1.0"
)

@app.get("/api/test")
def test_endpoint():
    return {"test": "ok"}

@app.get("/api/cluster/status")
def get_cluster_status():
    return {
        "status": "Healthy",
        "nodes": 5,
        "pods": 11
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)