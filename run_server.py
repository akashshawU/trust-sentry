"""Start the Trust Agent server."""
import os
import sys

# Ensure the project root is on the path
root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, root)

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "trust_agent.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
