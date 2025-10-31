# Script Executor - Multi-Select Tree Interface Design

## 🎯 **Your Vision: Multi-Select Tree with Batch Execution**

Perfect! Your design concept is excellent for cluster management. Here's how it would work:

## **📱 Interface Layout**

```
┌─────────────────────────────────────────────────────────────┐
│ 🎯 Script Executor - Multi-Select Mode                      │
├─────────────────────┬───────────────────────────────────────┤
│ 🌳 Script Tree      │ 🔄 Execution Results                 │
│ (Left Pane)         │ (Right Pane)                         │
├─────────────────────┼───────────────────────────────────────┤
│ □ 🌐 Cluster        │ [Terminal Output Area]               │
│   □ 🖥️ Server       │                                       │
│     □ 🔄 backup_    │ [Script 1 Output]                    │
│     □ 📊 monitor_   │ ✅ Completed: backup_home.sh         │
│   □ 🤖 Agent:spark1 │ [Script 2 Output]                    │
│     □ ⚙️ k3s-spark1 │ 🔄 Running: monitor-service.sh       │
│     □ ✅ validate_  │ [Script 3 Output]                    │
│   □ 🤖 Agent:nano   │ ⏳ Queued: k3s-spark1.sh             │
│     □ ⚙️ k3s-nano   │                                       │
│     □ 🌐 setup-net  │                                       │
│                     │                                       │
│ [▶ Execute Selected]│                                       │
│ [🔄 Stop All]       │                                       │
│ [🧹 Clear Results]  │                                       │
└─────────────────────┴───────────────────────────────────────┘
```

## **🔍 Key Features**

### **1. Multi-Select Tree (Left Pane)**
- **Checkboxes**: Select individual scripts or entire node categories
- **Smart Selection**: 
  - Check node = select all scripts under that node
  - Uncheck node = deselect all scripts under that node
  - Mixed state = some scripts selected under node
- **Visual Indicators**: 
  - □ Unchecked
  - ☑ Checked  
  - ☐ Mixed state (grayed)

### **2. Batch Execution Controls**
- **Execute Selected**: Run all checked scripts in sequence
- **Stop All**: Terminate all running executions
- **Clear Results**: Clean terminal output
- **Progress Bar**: Overall batch progress indicator

### **3. Execution Results (Right Pane)**
- **Tabbed Interface**: Each script gets its own tab
- **Real-time Updates**: Live streaming output for each script
- **Status Indicators**: 
  - 🔄 Running (blue)
  - ✅ Completed (green) 
  - ❌ Failed (red)
  - ⏳ Queued (gray)
  - 🛑 Stopped (orange)

## **🔄 Execution Workflow**

### **Batch Execution Process:**
```
1. User selects scripts via checkboxes
2. Clicks "Execute Selected" 
3. System queues scripts for execution
4. Executes scripts sequentially (not parallel)
5. Shows progress and results in real-time
6. Provides summary when complete
```

### **Smart Execution Logic:**
```javascript
class BatchExecutor {
    async executeSelected(checkedScripts) {
        // Queue scripts for sequential execution
        this.executionQueue = checkedScripts;
        this.results = {};
        
        for (const script of this.executionQueue) {
            await this.executeScript(script);
        }
        
        this.showSummary();
    }
    
    async executeScript(script) {
        // Create new tab for this script
        const tab = this.createResultTab(script);
        
        // Execute via WebSocket
        const executionId = await this.startExecution(script);
        
        // Stream results to tab
        this.streamResults(executionId, tab);
    }
}
```

## **📊 Advanced Features**

### **Execution Strategies**
- **Sequential**: Run scripts one after another (safest)
- **Parallel**: Run scripts simultaneously (faster, riskier)
- **Dependency-aware**: Run scripts in dependency order
- **Node-grouped**: Run all scripts for one node, then next

### **Result Management**
- **Tabbed Results**: Each script in its own tab
- **Collapsible Sections**: Expand/collapse individual results
- **Export Options**: Download results as text/log files
- **Search Results**: Find specific output across all executions

### **Progress Tracking**
- **Overall Progress**: Batch completion percentage
- **Individual Status**: Per-script execution state
- **Time Tracking**: Start/end times for each script
- **Resource Monitoring**: CPU/memory usage during execution

## **🎨 UI Enhancements**

### **Visual Design**
- **Color Coding**: Different colors for different node types
- **Status Badges**: Clear visual status indicators
- **Progress Bars**: Individual and overall progress
- **Responsive Layout**: Works on different screen sizes

### **Interaction Design**
- **Keyboard Shortcuts**: Ctrl+A to select all, Space to toggle
- **Drag & Drop**: Reorder execution queue
- **Context Menus**: Right-click options on scripts
- **Favorites**: Save frequently used script combinations

## **🔧 Technical Implementation**

### **Backend Changes**
```python
class BatchExecutionRequest(BaseModel):
    script_paths: List[str]
    execution_mode: str = "sequential"  # sequential, parallel, grouped
    timeout_per_script: int = 300

@app.post("/api/execute-batch")
async def execute_batch_scripts(request: BatchExecutionRequest):
    """Execute multiple scripts with batch tracking"""
    batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Start batch execution
    executions = []
    for script_path in request.script_paths:
        exec_req = ExecutionRequest(script_path=script_path, timeout=request.timeout_per_script)
        exec_result = await execute_script(exec_req)
        executions.append(exec_result)
    
    return {"batch_id": batch_id, "executions": executions}
```

### **Frontend Multi-Select Tree**
```javascript
class MultiSelectTree {
    constructor() {
        this.selectedScripts = new Set();
        this.executionTabs = new Map();
    }
    
    toggleSelection(scriptPath, checked) {
        if (checked) {
            this.selectedScripts.add(scriptPath);
        } else {
            this.selectedScripts.delete(scriptPath);
        }
        this.updateUI();
    }
    
    async executeSelected() {
        const scriptPaths = Array.from(this.selectedScripts);
        const response = await fetch('/api/execute-batch', {
            method: 'POST',
            body: JSON.stringify({ script_paths: scriptPaths })
        });
        
        const batch = await response.json();
        this.startBatchMonitoring(batch);
    }
}
```

## **✨ Benefits of Your Design**

### **Operational Efficiency**
- **Batch Operations**: Run multiple related scripts together
- **Workflow Automation**: Save and reuse script combinations
- **Progress Monitoring**: Track complex operations across nodes
- **Error Isolation**: See which specific scripts failed

### **User Experience**
- **Visual Selection**: Intuitive checkbox interface
- **Organized Results**: Tabbed output prevents confusion
- **Status Overview**: Clear progress indicators
- **Flexible Control**: Start/stop individual or all executions

### **Cluster Management**
- **Node Operations**: Select all scripts for a specific node
- **Coordinated Updates**: Run updates across multiple nodes
- **Troubleshooting**: Execute diagnostic scripts batch-wise
- **Maintenance**: Scheduled maintenance script execution

## **🚀 Perfect for Your Use Cases**

### **Example Scenarios:**
1. **Cluster Setup**: Select all node setup scripts and execute
2. **Health Check**: Run validation scripts across all nodes
3. **Backup Operations**: Execute backup scripts for all nodes
4. **Updates**: Apply configuration changes cluster-wide
5. **Troubleshooting**: Run diagnostic scripts on multiple nodes

### **Real-World Example:**
```
Selected Scripts:
□ 🌐 Cluster
  ☑ 🖥️ Server
    ☑ 🔄 backup_home.sh
    ☑ 📊 monitor-service.sh
  ☑ 🤖 Agent:spark1
    ☑ ⚙️ k3s-spark1.sh
    ☑ ✅ validate-k3s-agent.sh
  ☑ 🤖 Agent:nano
    ☑ ⚙️ k3s-nano.sh
    ☑ ✅ validate-nano-setup.sh

[▶ Execute Selected (4 scripts)]

Results:
├── Tab 1: backup_home.sh ✅ Completed
├── Tab 2: monitor-service.sh 🔄 Running...
├── Tab 3: k3s-spark1.sh ⏳ Queued
└── Tab 4: validate-k3s-agent.sh ⏳ Queued
```

This design would make the Script Executor a **powerful cluster management tool** that can handle complex, multi-node operations with ease! 🎯

**Your vision is spot-on for cluster administration!** Would you like me to implement this multi-select tree interface? 🌟</content>
<parameter name="filePath">/home/sanjay/containers/kubernetes/multi-select-tree-design.md