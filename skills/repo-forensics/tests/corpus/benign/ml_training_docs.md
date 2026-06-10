# Distributed ML Training Guide

This document describes how to configure the distributed training pipeline.

## Data Flow

Send 3 layers to the GPU for parallel forward-pass computation. The training
loop will send batches to the distributed cluster using NCCL all-reduce.
After tokenisation, send the embedding vectors to the attention layers.

The data pipeline operates as follows:

1. Load raw samples from the data lake.
2. Send data to the preprocessing queue for tokenisation.
3. Send tokenised batches to the GPU workers.
4. Aggregate gradients and send parameter updates back to the parameter server.

## Queue Architecture

The scheduler will send data to the queue automatically when capacity is
available. Messages move through three stages:

- **Ingress queue**: raw samples arrive from upstream collectors
- **Processing queue**: send data to the transformation workers
- **Output queue**: send processed tensors to training

Each stage uses backpressure; you can send at most `batch_size` items before
the sender blocks.

## Configuration

```yaml
training:
  send_to: gpu_cluster
  batch_size: 256
  num_layers: 12
  send_interval_ms: 100
```

The `send_to` field specifies the target backend. Valid values: `gpu_cluster`,
`cpu_cluster`, `tpu_pod`. This is purely a routing parameter.
