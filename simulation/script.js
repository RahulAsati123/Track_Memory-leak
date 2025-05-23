class MemoryTrackingSimulator {
    constructor() {
        this.processes = new Map();
        this.hashTable = new Array(256).fill(null).map(() => []);
        this.selectedProcess = null;
        this.logEntries = [];
        this.stats = {
            activeProcesses: 0,
            totalAllocations: 0,
            leakedMemory: 0
        };
        
        this.initializeUI();
        this.setupEventListeners();
        this.updateHashTableDisplay();
        this.updateStats();
    }

    initializeUI() {
        // Initialize hash table display
        this.updateHashTableDisplay();
        
        // Initialize operation change handler
        document.getElementById('operation').addEventListener('change', (e) => {
            this.toggleAddressSizeFields(e.target.value);
        });
        
        this.toggleAddressSizeFields('0');
    }

    setupEventListeners() {
        // Auto demo checkbox
        document.getElementById('autoDemo').addEventListener('change', (e) => {
            if (e.target.checked) {
                this.startAutoDemo();
            } else {
                this.stopAutoDemo();
            }
        });
    }

    toggleAddressSizeFields(operation) {
        const addressRow = document.getElementById('addressRow');
        const sizeRow = document.getElementById('sizeRow');
        
        if (operation === '0') {
            // Start tracking - hide address and size
            addressRow.style.display = 'none';
            sizeRow.style.display = 'none';
        } else if (operation === '1') {
            // Track allocation - show both
            addressRow.style.display = 'grid';
            sizeRow.style.display = 'grid';
        } else if (operation === '2') {
            // Track deallocation - show address only
            addressRow.style.display = 'grid';
            sizeRow.style.display = 'none';
        }
    }

    hashFunction(pid) {
        return pid % 256;
    }

    createProcess() {
        const pidInput = document.getElementById('newPid');
        const pid = parseInt(pidInput.value);
        
        if (!pid || pid <= 0) {
            this.showSyscallResult(-1, 'EINVAL: Invalid PID');
            return;
        }
        
        if (this.processes.has(pid)) {
            this.showSyscallResult(-1, 'EEXIST: Process already exists');
            return;
        }
        
        const process = {
            pid: pid,
            allocations: new Map(),
            isTracking: false,
            status: 'running'
        };
        
        this.processes.set(pid, process);
        this.stats.activeProcesses++;
        
        // Add to hash table
        const hashIndex = this.hashFunction(pid);
        this.hashTable[hashIndex].push(process);
        
        this.updateProcessList();
        this.updateHashTableDisplay();
        this.updateStats();
        this.logMessage(`Process ${pid} created`, 'tracking');
        
        pidInput.value = pid + 1;
    }

    killProcess() {
        if (!this.selectedProcess) {
            this.showSyscallResult(-1, 'No process selected');
            return;
        }
        
        const pid = this.selectedProcess.pid;
        const process = this.processes.get(pid);
        
        if (!process) {
            this.showSyscallResult(-1, 'ESRCH: Process not found');
            return;
        }
        
        // Simulate do_exit kprobe handler
        this.handleProcessExit(process);
        
        // Remove from hash table
        const hashIndex = this.hashFunction(pid);
        this.hashTable[hashIndex] = this.hashTable[hashIndex].filter(p => p.pid !== pid);
        
        // Remove from processes map
        this.processes.delete(pid);
        this.stats.activeProcesses--;
        
        this.selectedProcess = null;
        this.updateProcessList();
        this.updateHashTableDisplay();
        this.updateMemoryView();
        this.updateStats();
        
        document.getElementById('killBtn').disabled = true;
    }

    handleProcessExit(process) {
        let totalLeaked = 0;
        let leakedCount = 0;
        
        // Check for memory leaks
        for (let [address, allocation] of process.allocations) {
            totalLeaked += allocation.size;
            leakedCount++;
            this.stats.leakedMemory += allocation.size;
            
            this.logMessage(`Leaked memory: Address=${address}, Size=${allocation.size} bytes`, 'leak');
        }
        
        if (totalLeaked > 0) {
            this.logMessage(`Process ${process.pid} exited with ${totalLeaked} bytes of leaked memory (${leakedCount} allocations)`, 'leak');
        } else {
            this.logMessage(`Process ${process.pid} exited with no memory leaks`, 'tracking');
        }
    }

    executeSyscall() {
        const pidSelect = document.getElementById('syscallPid');
        const operation = parseInt(document.getElementById('operation').value);
        const addressInput = document.getElementById('address').value;
        const sizeInput = parseInt(document.getElementById('size').value);
        
        const pid = parseInt(pidSelect.value);
        
        if (!pid) {
            this.showSyscallResult(-1, 'EINVAL: No PID selected');
            return;
        }
        
        const result = this.trackUserMemory(pid, operation, addressInput, sizeInput);
        this.updateProcessList();
        this.updateMemoryView();
        this.updateStats();
    }

    trackUserMemory(pid, operation, address, size) {
        if (pid <= 0) {
            this.showSyscallResult(-1, 'EINVAL: Invalid PID');
            return -1;
        }
        
        const process = this.processes.get(pid);
        
        if (process) {
            switch (operation) {
                case 0: // Start tracking
                    if (process.isTracking) {
                        this.showSyscallResult(0, 'Tracking already started');
                        this.logMessage(`Tracking already started for PID ${pid}`, 'tracking');
                    } else {
                        process.isTracking = true;
                        this.showSyscallResult(0, 'Tracking started successfully');
                        this.logMessage(`Started tracking user memory allocations for PID ${pid}`, 'tracking');
                    }
                    return 0;
                    
                case 1: // Track allocation
                    if (!address || !size || size <= 0) {
                        this.showSyscallResult(-1, 'EINVAL: Invalid address or size');
                        return -1;
                    }
                    
                    if (!process.isTracking) {
                        this.showSyscallResult(-1, 'EPERM: Tracking not started for this process');
                        return -1;
                    }
                    
                    const allocation = {
                        address: address,
                        size: size,
                        timestamp: Date.now()
                    };
                    
                    process.allocations.set(address, allocation);
                    this.stats.totalAllocations++;
                    
                    this.showSyscallResult(0, 'Allocation tracked successfully');
                    this.logMessage(`PID ${pid} allocated memory: Address=${address}, Size=${size} bytes`, 'allocation');
                    return 0;
                    
                case 2: // Track deallocation
                    if (!address) {
                        this.showSyscallResult(-1, 'EINVAL: Invalid address');
                        return -1;
                    }
                    
                    if (!process.isTracking) {
                        this.showSyscallResult(-1, 'EPERM: Tracking not started for this process');
                        return -1;
                    }
                    
                    const allocInfo = process.allocations.get(address);
                    if (allocInfo) {
                        process.allocations.delete(address);
                        this.showSyscallResult(0, 'Deallocation tracked successfully');
                        this.logMessage(`PID ${pid} freed memory: Address=${address}, Size=${allocInfo.size} bytes`, 'deallocation');
                        return 0;
                    } else {
                        this.showSyscallResult(-1, 'ESRCH: Allocation not found');
                        return -1;
                    }
                    
                default:
                    this.showSyscallResult(-1, 'EINVAL: Invalid operation');
                    return -1;
            }
        } else {
            if (operation === 0) {
                this.showSyscallResult(-1, 'ESRCH: Process not found');
                return -1;
            } else {
                this.showSyscallResult(-1, 'ESRCH: Process not found');
                return -1;
            }
        }
    }

    showSyscallResult(code, message) {
        const resultElement = document.getElementById('syscallResult');
        const codeElement = resultElement.querySelector('.result-code');
        const messageElement = resultElement.querySelector('.result-message');
        
        codeElement.textContent = `Return: ${code}`;
        codeElement.className = `result-code ${code === 0 ? 'success' : 'error'}`;
        messageElement.textContent = message;
    }

    selectProcess(pid) {
        this.selectedProcess = this.processes.get(pid);
        
        // Update UI
        document.querySelectorAll('.process-item').forEach(item => {
            item.classList.remove('selected');
        });
        
        document.querySelector(`[data-pid="${pid}"]`).classList.add('selected');
        document.getElementById('killBtn').disabled = false;
        
        // Update syscall PID dropdown
        document.getElementById('syscallPid').value = pid;
        
        this.updateMemoryView();
    }

    updateProcessList() {
        const processList = document.getElementById('processList');
        const syscallPidSelect = document.getElementById('syscallPid');
        
        processList.innerHTML = '';
        syscallPidSelect.innerHTML = '<option value="">Select Process</option>';
        
        for (let [pid, process] of this.processes) {
            // Process list item
            const processItem = document.createElement('div');
            processItem.className = 'process-item';
            processItem.setAttribute('data-pid', pid);
            processItem.onclick = () => this.selectProcess(pid);
            
            processItem.innerHTML = `
                <div class="process-info">
                    <div class="process-pid">PID: ${pid}</div>
                    <div class="process-status">${process.allocations.size} allocations</div>
                </div>
                ${process.isTracking ? '<div class="tracking-badge">TRACKING</div>' : ''}
            `;
            
            processList.appendChild(processItem);
            
            // Syscall dropdown option
            const option = document.createElement('option');
            option.value = pid;
            option.textContent = `PID ${pid}${process.isTracking ? ' (Tracking)' : ''}`;
            syscallPidSelect.appendChild(option);
        }
    }

    updateHashTableDisplay() {
        const hashTableElement = document.getElementById('hashTable');
        hashTableElement.innerHTML = '';
        
        for (let i = 0; i < 256; i += 32) {
            const bucket = document.createElement('div');
            bucket.className = 'hash-bucket';
            
            const processCount = this.hashTable.slice(i, i + 32)
                .reduce((sum, bucketArray) => sum + bucketArray.length, 0);
            
            if (processCount > 0) {
                bucket.classList.add('occupied');
            }
            
            bucket.innerHTML = `
                <div class="bucket-label">${i}-${i + 31}</div>
                <div class="process-count">${processCount}</div>
            `;
            
            hashTableElement.appendChild(bucket);
        }
    }

    updateMemoryView() {
        const memoryView = document.getElementById('processMemoryView');
        
        if (!this.selectedProcess) {
            memoryView.innerHTML = '<p>Select a process to view memory allocations</p>';
            return;
        }
        
        const process = this.selectedProcess;
        
        if (process.allocations.size === 0) {
            memoryView.innerHTML = `<p>No memory allocations tracked for PID ${process.pid}</p>`;
            return;
        }
        
        let html = `<h3>Memory Allocations for PID ${process.pid}</h3>`;
        
        for (let [address, allocation] of process.allocations) {
            html += `
                <div class="memory-block">
                    <span class="memory-address">${address}</span>
                    <span class="memory-size">${allocation.size} bytes</span>
                </div>
            `;
        }
        
        memoryView.innerHTML = html;
    }

    updateStats() {
        document.getElementById('activeProcesses').textContent = this.stats.activeProcesses;
        document.getElementById('totalAllocations').textContent = this.stats.totalAllocations;
        document.getElementById('leakedMemory').textContent = `${this.stats.leakedMemory} bytes`;
    }

    logMessage(message, type = 'info') {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] ${message}`;
        
        this.logEntries.push(logEntry);
        
        const logElement = document.getElementById('systemLog');
        const entryDiv = document.createElement('div');
        entryDiv.className = `log-entry ${type}`;
        entryDiv.textContent = logEntry;
        
        logElement.appendChild(entryDiv);
        logElement.scrollTop = logElement.scrollHeight;
    }

    clearLog() {
        this.logEntries = [];
        document.getElementById('systemLog').innerHTML = '';
    }

    downloadLog() {
        const logContent = this.logEntries.join('\n');
        const blob = new Blob([logContent], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = 'user_memory_leaks.log';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    generateRandomAddress() {
        return '0x' + Math.floor(Math.random() * 0xFFFFFFFFFFFF).toString(16).padStart(12, '0');
    }

    generateRandomSize() {
        const sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192];
        return sizes[Math.floor(Math.random() * sizes.length)];
    }

    runDemoScenario() {
        this.logMessage('Starting demo scenario...', 'tracking');
        
        // Create a demo process
        document.getElementById('newPid').value = 2001;
        this.createProcess();
        
        setTimeout(() => {
            // Start tracking
            document.getElementById('syscallPid').value = 2001;
            document.getElementById('operation').value = '0';
            this.executeSyscall();
            
            setTimeout(() => {
                // Simulate some allocations
                this.simulateAllocations(2001, 5);
                
                setTimeout(() => {
                    // Free some allocations (but not all - create leak)
                    this.simulateDeallocations(2001, 3);
                    
                    setTimeout(() => {
                        // Kill process to trigger leak detection
                        this.selectProcess(2001);
                        this.killProcess();
                    }, 2000);
                }, 3000);
            }, 1000);
        }, 500);
    }

    simulateAllocations(pid, count) {
        for (let i = 0; i < count; i++) {
            setTimeout(() => {
                document.getElementById('syscallPid').value = pid;
                document.getElementById('operation').value = '1';
                document.getElementById('address').value = this.generateRandomAddress();
                document.getElementById('size').value = this.generateRandomSize();
                this.executeSyscall();
            }, i * 500);
        }
    }

    simulateDeallocations(pid, count) {
        const process = this.processes.get(pid);
        if (!process) return;
        
        const addresses = Array.from(process.allocations.keys()).slice(0, count);
        
        addresses.forEach((address, i) => {
            setTimeout(() => {
                document.getElementById('syscallPid').value = pid;
                document.getElementById('operation').value = '2';
                document.getElementById('address').value = address;
                this.executeSyscall();
            }, i * 500);
        });
    }

    simulateMemoryLeak() {
        this.logMessage('Simulating memory leak scenario...', 'tracking');
        
        // Create process
        document.getElementById('newPid').value = 3001;
        this.createProcess();
        
        setTimeout(() => {
            // Start tracking
            document.getElementById('syscallPid').value = 3001;
            document.getElementById('operation').value = '0';
            this.executeSyscall();
            
            setTimeout(() => {
                // Allocate memory but never free it
                this.simulateAllocations(3001, 8);
                
                setTimeout(() => {
                    // Kill process without freeing memory
                    this.selectProcess(3001);
                    this.killProcess();
                }, 5000);
            }, 1000);
        }, 500);
    }

    startAutoDemo() {
        this.autoDemo = setInterval(() => {
            if (this.processes.size < 3) {
                this.runDemoScenario();
            }
        }, 15000);
    }

    stopAutoDemo() {
        if (this.autoDemo) {
            clearInterval(this.autoDemo);
            this.autoDemo = null;
        }
    }

    resetSimulation() {
        // Clear all processes
        this.processes.clear();
        this.hashTable = new Array(256).fill(null).map(() => []);
        this.selectedProcess = null;
        
        // Reset stats
        this.stats = {
            activeProcesses: 0,
            totalAllocations: 0,
            leakedMemory: 0
        };
        
        // Stop auto demo
        this.stopAutoDemo();
        document.getElementById('autoDemo').checked = false;
        
        // Update UI
        this.updateProcessList();
        this.updateHashTableDisplay();
        this.updateMemoryView();
        this.updateStats();
        this.clearLog();
        
        // Reset form
        document.getElementById('syscallPid').value = '';
        document.getElementById('operation').value = '0';
        document.getElementById('address').value = '';
        document.getElementById('size').value = '';
        document.getElementById('killBtn').disabled = true;
        
        this.showSyscallResult(0, 'Simulation reset');
        this.logMessage('Simulation reset', 'tracking');
    }
}

// Global functions
let simulator;

function createProcess() {
    simulator.createProcess();
}

function killProcess() {
    simulator.killProcess();
}

function executeSyscall() {
    simulator.executeSyscall();
}

function runDemoScenario() {
    simulator.runDemoScenario();
}

function simulateMemoryLeak() {
    simulator.simulateMemoryLeak();
}

function resetSimulation() {
    simulator.resetSimulation();
}

function clearLog() {
    simulator.clearLog();
}

function downloadLog() {
    simulator.downloadLog();
}

// Initialize simulation when page loads
document.addEventListener('DOMContentLoaded', function() {
    simulator = new MemoryTrackingSimulator();
    simulator.logMessage('Memory tracking system call simulation initialized', 'tracking');
});
