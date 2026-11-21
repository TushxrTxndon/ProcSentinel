# Linux environment for running ProcSentinel on Windows/macOS hosts.
#   docker build -t procsentinel .
#   docker run --rm -it --init -p 127.0.0.1:8080:8080 procsentinel
# Add --pid=host to monitor every process of the Docker VM instead of just the container.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      g++ cmake make python3 python3-numpy python3-sklearn \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN sed -i 's/\r$//' run.sh && chmod +x run.sh \
    && cmake -S collector -B collector/build -DCMAKE_BUILD_TYPE=Release && cmake --build collector/build \
    && make -C workloads
EXPOSE 8080
CMD ["./run.sh", "--host", "0.0.0.0"]
