Below is a detailed flowchart illustrating the architecture and data flow of the audit processing system. Steps that correspond to specific source files are color-coded for clarity, though not all steps are mapped yet. Feel free to let me (Callie) know if you have suggestions.

```mermaid
flowchart TD
    subgraph "Startup Phase"
        ST[Start Process] --> RC[Read Config File]
        RC --> VC[Validate Config]
        VC --> RR[Read Audit Rules]
        RR --> LR[Load Rules to Kernel]
        LR --> IS[Initialize Subsystems]
        IS --> OS[Open Netlink Socket]
    end
    
    subgraph "Runtime Phase"
        A[Raw Netlink Message] --> B[Parse Preamble]
        B --> C[Parse Fields]
        C --> D[Create AuditRecord]
        
        D --> E{Record Type?}
        E -->|Complex Event| F[Correlator Buffer]
        E -->|Simple Event| G[Filter Engine]
        
        F -->|Complete Event| G
        G -->|Passed Filter| H[Output Writer]
        G -->|Dropped| I[Drop]
        
        H --> J{Output Format?}
        J -->|JSON| K[JSON Serializer]
        J -->|Legacy| L[Legacy Formatter]
        
        K --> M[Log File]
        L --> M
    end
    
    subgraph "Signal Handling"
        SIG[SIGHUP Signal] --> RC2[Reload Config]
        RC2 --> VC2[Validate Config]
        VC2 --> UP[Update Runtime Settings]
    end
    
    OS --> A
    
    classDef parser fill:#e8f5e8,stroke:#388e3c,stroke-width:3px
    classDef correlator fill:#fff3e0,stroke:#f57c00,stroke-width:3px
    classDef filter fill:#f3e5f5,stroke:#7b1fa2,stroke-width:3px
    classDef writer fill:#fce4ec,stroke:#c2185b,stroke-width:3px
    classDef unknown fill:#f5f5f5,stroke:#757575,stroke-width:2px
    
    class B,C,D parser
    class E,F correlator
    class G filter
    class H,J,K,L,M writer
    class ST,RC,VC,RR,LR,IS,OS,A,SIG,RC2,VC2,UP,I unknown
```

- 🟢 **Green** - `parser.rs`
- 🟠 **Orange** - `correlator.rs`
- 🟣 **Purple** - `filter.rs`
- 🔴 **Red** - `writer.rs`
- ⚪ **Gray** - TBD