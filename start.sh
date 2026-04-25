#!/bin/bash
# start.sh

# شغل Uvicorn في الخلفية
uvicorn service:app --host 0.0.0.0 --port ${PORT:-8002} --log-level info &

# شغل consumer.py
python consumer.py

# انتظر أي عملية تنتهي
wait
