# Terms and Definitions
- **Audit Record**: A structured representation of an audit event, containing fields such as timestamp, event type, user ID, etc.
- **Audit Event**: A single occurrence of an action or operation that is logged by the audit system.
  - **Simple Event** - An event that is fully contained within a single audit record.
  - **Complex Event** - An event that spans multiple audit records. Correlated via PID and timestamp.
- **Audit Rules**: Configurations applied to the kernel to specify what events are emitted.
  - These are loaded from a rules file at startup. Since it talks to the kernel, we should keep the legacy format.
  - The legacy format is quite opaque, so writing our own wrapper around it is a stretch goal.
- **Audit Filters**: User-defined criteria to determine which audit records should be logged or discarded.
  - This lives completely in userspace, meaning we have free reign to define our own format.
- **Configurations**: Any setting that is not a filter or rule, such as log file paths, log rotation policies, etc. These are all managed in userspace.

# Program flowchart
Below is a detailed flowchart illustrating the architecture and data flow of the audit processing system.

```mermaid
---
title: Program Architecture
config:
  theme: forest
---
graph LR
    subgraph "External Sources"
        Kernel[Linux Kernel<br/>Netlink Socket]
        RulesFile[Audit Rules File]
        ConfigFile[Config File]
        FiltersFile[Audit Filters File]
        SIGHUP[SIGHUP Signal]
    end
  
    subgraph "Supporting Components"
        Config[Config Manager]
        NetlinkReader[Netlink Socket Reader]
    end

    subgraph "Core Components"
        Parser[Parser]
        Correlator[Correlator]
        Filter[Filter]
        Writer[Writer]
        Raw@{shape: lean-r, label: "Raw Record Lines"}
        Parsed@{shape: lean-r, label: "Parsed Records"}
        Events@{shape: lean-r, label: "Events"}
    end
    
    subgraph "Outputs"
        LogFiles[(Log Files)]
        
    end
  
    RulesFile --> Kernel
    FiltersFile <--> | Combine? | ConfigFile
  
    ConfigFile --> Config
    FiltersFile --> Config
    SIGHUP --> Config
  
    Config --> Filter
    Config --> Writer
    Kernel --> NetlinkReader
  
    NetlinkReader --> Raw --> Parser
    Parser --> Parsed --> Correlator
    Correlator --> Events --> Filter
    Filter --> Writer
    Writer --> LogFiles
    
    classDef parser fill:#e8f5e8,stroke:#388e3c,stroke-width:3px
    classDef correlator fill:#fff3e0,stroke:#f57c00,stroke-width:3px
    classDef filter fill:#f3e5f5,stroke:#7b1fa2,stroke-width:3px
    classDef writer fill:#fce4ec,stroke:#c2185b,stroke-width:3px
    classDef support fill:#f5f5f5,stroke:#757575,stroke-width:2px
    
    class Parser parser
    class Correlator correlator
    class Filter filter
    class Writer writer
    class Config,NetlinkReader support
```

Notes:
- There are definitely optimizations that this flowchart does not cover, such as skipping correlation for simple events, or early filtering.
- This flowchart is probably not complete, and may be missing components. This is all I (callie!) could wrap my head around though.