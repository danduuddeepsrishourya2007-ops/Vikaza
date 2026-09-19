# NEXUS Benchmarks and Performance Testing

## Benchmarking Philosophy
NEXUS benchmarking focuses on measuring the platform's ability to:
- Run deterministic simulations at scale
- Separate simulation performance from LLM inference latency
- Provide reproducible results for policy comparison
- Scale to hundreds of simultaneous simulated agents

## Key Metrics

### Simulation Performance
- **Ticks per second**: Deterministic simulation steps processed per second
- **Agent update latency**: Time to process all agent decisions per tick
- **Memory usage per agent**: RAM consumption for maintaining agent state
- **Deterministic overhead**: Performance cost of ensuring reproducibility

### LLM Integration Performance
- **Inference throughput**: Number of LLM calls processed per second
- **Average response time**: Latency for LLM-guided decisions
- **Batching efficiency**: Improvement from batched vs. sequential inference
- **Concurrent request handling**: Ability to manage multiple simultaneous LLM requests

### Scalability Metrics
- **Maximum agents supported**: Upper limit before performance degradation
- **Performance degradation curve**: How performance changes with agent count
- **Resource utilization efficiency**: CPU, GPU, and memory usage patterns
- **Horizontal scaling characteristics**: Performance when adding compute resources

## Benchmark Categories

### Core Simulation Benchmarks
1. **Empty World Simulation**: Base performance with no agents
2. **Deterministic Agent Agents**: Performance with rule-based agents only
3. **Hybrid Agent Mix**: Performance with combination of deterministic and LLM agents
4. **Stress Testing**: Performance under maximum load conditions

### Cyber-Specific Benchmarks (Nexus Cyber)
1. **Baseline Network Simulation**: Performance modeling network infrastructure
2. **Attack Propagation Speed**: How quickly threats spread through simulated environment
3. **Defense Response Time**: Time for simulated security teams to react
4. **Policy Comparison Overhead**: Additional cost of running multiple policy scenarios

## Planned Benchmark Suite

### Deterministic Mechanics Tests
- World state update performance
- Event queue processing speed
- Dependency resolution efficiency
- Resource tracking overhead

### LLM Integration Tests
- Single inference call latency
- Batched inference throughput
- Concurrent request handling
- Prompt processing overhead
- Response parsing efficiency

### Scenario-Based Benchmarks
- Incident response timeline accuracy
- Policy comparison completion time
- Recovery scenario validation
- Cascade failure modeling precision

## Reporting Standards

All benchmarks will report:
- **Hardware specifications**: CPU, GPU, RAM, storage details
- **Software versions**: Python, library versions, OS details
- **Configuration parameters**: Simulation settings, LLM parameters, etc.
- **Measurement methodology**: How measurements were taken
- **Statistical significance**: Sample sizes, confidence intervals, variance
- **Reproducibility instructions**: How others can reproduce results

## Initial Benchmark Focus
Initial benchmarks will establish baseline performance for:
1. Core simulation engine without agents
2. Simple deterministic agent behaviors
3. Basic LLM integration pathways
4. Minimal viable scenario execution

## Benchmark Environment
Planned benchmark infrastructure:
- AMD Instinct MI300X GPUs
- ROCm software stack
- vLLM inference server
- Sufficient CPU and memory to avoid bottlenecks
- Controlled network conditions for consistent testing

## Success Criteria for Benchmarks
- Linear or near-linear scaling with agent count (up to target)
- Deterministic results across multiple runs with same seed
- Clear separation between simulation and LLM performance metrics
- Ability to compare policy outcomes with statistical significance
- Reproducible results across different hardware configurations (within reason)