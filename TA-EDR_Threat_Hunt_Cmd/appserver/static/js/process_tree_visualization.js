/**
 * Enhanced EDR Process Tree Visualization
 * 
 * Improved visualization for displaying process execution trees from EDR telemetry
 * Supports CrowdStrike, SentinelOne, and Defender data formats
 * 
 * Features:
 * - Better performance for large process trees
 * - Enhanced interactivity including node expansion/collapse
 * - Improved filtering and search capabilities
 * - Better visualization styling and responsiveness
 * - Cross-browser compatibility
 */

require([
    'jquery',
    'underscore',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!',
    'splunkjs/mvc/d3'
], function($, _, mvc, ready, d3) {
    
    // Define the enhanced visualization
    const ProcessTreeViz = {
        /**
         * Initialize the visualization
         * @param {Object} element - DOM element to render in
         * @param {Object} settings - Visualization settings
         */
        initialize: function(element, settings) {
            this.el = element;
            this.settings = this._mergeSettings(settings || {});
            this.data = null;
            this.filteredData = null;
            this.selectedNode = null;
            this.expandedNodes = new Set();
            this.searchTerm = '';
            
            // Create the container
            this._createContainer();
            
            // Create the SVG container
            this._createSvgContainer();
            
            // Create control panel
            this._createControlPanel();
                
            // Create tooltips
            this._createTooltip();
                
            // Style the visualization
            this._applyStyles();
            
            // Track window resize events for responsiveness
            this._setupResizeHandler();
        },
        
        /**
         * Merge user settings with defaults
         * @param {Object} userSettings - User provided settings
         * @returns {Object} - Merged settings
         */
        _mergeSettings: function(userSettings) {
            // Default settings
            const defaults = {
                nodeSize: 20,
                maxDepth: 5,
                horizontalSpacing: 180,
                verticalSpacing: 40,
                showCommandLine: true,
                colorByProvider: false,
                initialCollapseDepth: 3,
                minHeight: 400,
                maxHeight: 1200,
                animationDuration: 500,
                treeLayout: 'horizontal', // 'horizontal' or 'vertical'
                theme: 'dark', // 'dark' or 'light'
                searchHighlightColor: '#F82B60',
                processIconType: 'circle' // 'circle' or 'icon'
            };
            
            // Merge with user settings
            return $.extend({}, defaults, userSettings);
        },
        
        /**
         * Create the container for the visualization
         */
        _createContainer: function() {
            $(this.el).addClass('edr-process-tree-container');
            
            // Add wrapper for visualization and controls
            this.$wrapper = $('<div class="edr-process-tree-wrapper"></div>').appendTo($(this.el));
            
            // Apply theme class
            $(this.el).addClass('theme-' + this.settings.theme);
        },
        
        /**
         * Create SVG container for the visualization
         */
        _createSvgContainer: function() {
            // Create SVG container with responsive sizing
            this.svg = d3.select(this.el)
                .select('.edr-process-tree-wrapper')
                .append('div')
                .attr('class', 'edr-process-tree-svg-container')
                .append('svg')
                .attr('width', '100%')
                .attr('height', this.settings.minHeight)
                .append('g')
                .attr('transform', 'translate(40, 20)');
                
            // Create a background rect to capture events
            this.svg.append('rect')
                .attr('class', 'background')
                .attr('width', '100%')
                .attr('height', '100%')
                .attr('fill', 'transparent');
                
            // Create zoom behavior
            this.zoom = d3.zoom()
                .scaleExtent([0.25, 3])
                .on('zoom', (event) => {
                    d3.select(this.el).select('.edr-process-tree-svg-container svg g').attr('transform', event.transform);
                });
                
            d3.select(this.el).select('.edr-process-tree-svg-container svg').call(this.zoom);
            
            // Add reset zoom button
            this.$resetZoom = $('<button class="edr-process-tree-reset-zoom">Reset Zoom</button>')
                .appendTo($(this.el).find('.edr-process-tree-svg-container'))
                .on('click', () => {
                    this._resetZoom();
                });
                
            // Provider color scale
            this.providerColors = {
                'crowdstrike': '#F82B60',
                'sentinelone': '#00BFB3',
                'defender': '#0078D4',
                'default': '#808080'
            };
            
            // Process status color scale
            this.statusColors = d3.scaleOrdinal()
                .domain(['normal', 'terminated', 'suspicious', 'malicious'])
                .range(['#2E7D32', '#757575', '#FF9800', '#D32F2F']);
        },
        
        /**
         * Create the control panel
         */
        _createControlPanel: function() {
            // Create control panel container
            this.$controls = $('<div class="edr-process-tree-controls"></div>')
                .prependTo($(this.el).find('.edr-process-tree-wrapper'));
            
            // Add search box
            this.$searchBox = $('<div class="edr-process-tree-search">' +
                '<input type="text" placeholder="Search processes..." />' +
                '<button class="search-button">Search</button>' +
                '<button class="clear-button">Clear</button>' +
                '</div>')
                .appendTo(this.$controls);
                
            // Add search event handlers
            this.$searchBox.find('input').on('keyup', (e) => {
                if (e.key === 'Enter') {
                    this._handleSearch(this.$searchBox.find('input').val());
                }
            });
            
            this.$searchBox.find('.search-button').on('click', () => {
                this._handleSearch(this.$searchBox.find('input').val());
            });
            
            this.$searchBox.find('.clear-button').on('click', () => {
                this.$searchBox.find('input').val('');
                this._handleSearch('');
            });
            
            // Add toolbar
            this.$toolbar = $('<div class="edr-process-tree-toolbar"></div>')
                .appendTo(this.$controls);
                
            // Add expand/collapse all buttons
            this.$expandAll = $('<button class="edr-process-tree-expand-all">Expand All</button>')
                .appendTo(this.$toolbar)
                .on('click', () => {
                    this._expandAll();
                });
                
            this.$collapseAll = $('<button class="edr-process-tree-collapse-all">Collapse All</button>')
                .appendTo(this.$toolbar)
                .on('click', () => {
                    this._collapseAll();
                });
                
            // Add color mode toggle
            this.$colorToggle = $('<div class="edr-process-tree-color-toggle">' +
                '<label>Color by: ' +
                '<select>' +
                '<option value="status">Status</option>' +
                '<option value="provider">Provider</option>' +
                '</select>' +
                '</label>' +
                '</div>')
                .appendTo(this.$toolbar);
                
            this.$colorToggle.find('select').on('change', (e) => {
                this.settings.colorByProvider = $(e.target).val() === 'provider';
                this._updateNodeColors();
            });
            
            // Add layout toggle
            this.$layoutToggle = $('<div class="edr-process-tree-layout-toggle">' +
                '<label>Layout: ' +
                '<select>' +
                '<option value="horizontal">Horizontal</option>' +
                '<option value="vertical">Vertical</option>' +
                '</select>' +
                '</label>' +
                '</div>')
                .appendTo(this.$toolbar);
                
            this.$layoutToggle.find('select').on('change', (e) => {
                this.settings.treeLayout = $(e.target).val();
                this._redrawTree();
            });
            
            // Add filter section
            this.$filters = $('<div class="edr-process-tree-filters"></div>')
                .appendTo(this.$controls);
                
            // Add provider filter
            this.$providerFilter = $('<div class="edr-process-tree-filter">' +
                '<label>Provider: ' +
                '<select multiple>' +
                '<option value="all" selected>All</option>' +
                '<option value="crowdstrike">CrowdStrike</option>' +
                '<option value="sentinelone">SentinelOne</option>' +
                '<option value="defender">Defender</option>' +
                '</select>' +
                '</label>' +
                '</div>')
                .appendTo(this.$filters);
                
            this.$providerFilter.find('select').on('change', () => {
                this._applyFilters();
            });
            
            // Add status filter
            this.$statusFilter = $('<div class="edr-process-tree-filter">' +
                '<label>Status: ' +
                '<select multiple>' +
                '<option value="all" selected>All</option>' +
                '<option value="normal">Normal</option>' +
                '<option value="terminated">Terminated</option>' +
                '<option value="suspicious">Suspicious</option>' +
                '<option value="malicious">Malicious</option>' +
                '</select>' +
                '</label>' +
                '</div>')
                .appendTo(this.$filters);
                
            this.$statusFilter.find('select').on('change', () => {
                this._applyFilters();
            });
        },
        
        /**
         * Create tooltip
         */
        _createTooltip: function() {
            this.tooltip = d3.select('body')
                .append('div')
                .attr('class', 'edr-process-tree-tooltip')
                .style('opacity', 0);
        },
        
        /**
         * Set up resize handler for responsiveness
         */
        _setupResizeHandler: function() {
            $(window).on('resize', _.debounce(() => {
                this._handleResize();
            }, 200));
        },
        
        /**
         * Handle window resize
         */
        _handleResize: function() {
            if (!this.data) return;
            
            // Update SVG size
            const containerWidth = $(this.el).width();
            
            // Adjust height based on the number of nodes
            let height = this.settings.minHeight;
            
            if (this.data.length > 0) {
                const nodeCount = this._countNodes(this.data);
                height = Math.min(
                    this.settings.maxHeight,
                    Math.max(this.settings.minHeight, nodeCount * 25)
                );
            }
            
            // Update SVG dimensions
            d3.select(this.el).select('.edr-process-tree-svg-container svg')
                .attr('height', height);
                
            // Redraw the visualization
            this._redrawTree();
        },
        
        /**
         * Count total number of nodes in the tree
         * @param {Array} roots - Root nodes
         * @returns {number} - Total node count
         */
        _countNodes: function(roots) {
            let count = 0;
            
            const traverse = (node) => {
                count++;
                if (node.children) {
                    node.children.forEach(traverse);
                }
            };
            
            roots.forEach(traverse);
            
            return count;
        },
        
        /**
         * Apply CSS styles
         */
        _applyStyles: function() {
            // Add a style element if it doesn't exist
            if ($('#edr-process-tree-styles').length === 0) {
                const style = document.createElement('style');
                style.id = 'edr-process-tree-styles';
                style.textContent = `
                    .edr-process-tree-container {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        margin: 10px 0;
                        position: relative;
                    }
                    
                    .edr-process-tree-container.theme-dark {
                        color: #e0e0e0;
                    }
                    
                    .edr-process-tree-container.theme-light {
                        color: #333;
                    }
                    
                    .edr-process-tree-wrapper {
                        display: flex;
                        flex-direction: column;
                    }
                    
                    .edr-process-tree-controls {
                        margin-bottom: 10px;
                        padding: 10px;
                        border-radius: 4px;
                    }
                    
                    .theme-dark .edr-process-tree-controls {
                        background-color: rgba(30, 30, 30, 0.7);
                        border: 1px solid #444;
                    }
                    
                    .theme-light .edr-process-tree-controls {
                        background-color: rgba(245, 245, 245, 0.9);
                        border: 1px solid #ddd;
                    }
                    
                    .edr-process-tree-search {
                        display: flex;
                        margin-bottom: 10px;
                    }
                    
                    .edr-process-tree-search input {
                        flex: 1;
                        padding: 6px 10px;
                        border-radius: 4px 0 0 4px;
                        border: 1px solid #ccc;
                        border-right: none;
                        font-size: 14px;
                    }
                    
                    .theme-dark .edr-process-tree-search input {
                        background-color: #333;
                        color: #e0e0e0;
                        border-color: #555;
                    }
                    
                    .edr-process-tree-search button {
                        padding: 6px 12px;
                        border: 1px solid #ccc;
                        background-color: #f0f0f0;
                        cursor: pointer;
                        font-size: 14px;
                    }
                    
                    .theme-dark .edr-process-tree-search button {
                        background-color: #444;
                        color: #e0e0e0;
                        border-color: #555;
                    }
                    
                    .edr-process-tree-search button:hover {
                        background-color: #e0e0e0;
                    }
                    
                    .theme-dark .edr-process-tree-search button:hover {
                        background-color: #555;
                    }
                    
                    .edr-process-tree-search .search-button {
                        border-radius: 0;
                    }
                    
                    .edr-process-tree-search .clear-button {
                        border-radius: 0 4px 4px 0;
                    }
                    
                    .edr-process-tree-toolbar {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 10px;
                        margin-bottom: 10px;
                    }
                    
                    .edr-process-tree-toolbar button {
                        padding: 6px 12px;
                        border-radius: 4px;
                        border: 1px solid #ccc;
                        background-color: #f0f0f0;
                        cursor: pointer;
                        font-size: 14px;
                    }
                    
                    .theme-dark .edr-process-tree-toolbar button {
                        background-color: #444;
                        color: #e0e0e0;
                        border-color: #555;
                    }
                    
                    .edr-process-tree-toolbar button:hover {
                        background-color: #e0e0e0;
                    }
                    
                    .theme-dark .edr-process-tree-toolbar button:hover {
                        background-color: #555;
                    }
                    
                    .edr-process-tree-color-toggle,
                    .edr-process-tree-layout-toggle {
                        display: flex;
                        align-items: center;
                    }
                    
                    .edr-process-tree-color-toggle select,
                    .edr-process-tree-layout-toggle select {
                        margin-left: 5px;
                        padding: 5px;
                        border-radius: 4px;
                        border: 1px solid #ccc;
                    }
                    
                    .theme-dark .edr-process-tree-color-toggle select,
                    .theme-dark .edr-process-tree-layout-toggle select {
                        background-color: #444;
                        color: #e0e0e0;
                        border-color: #555;
                    }
                    
                    .edr-process-tree-filters {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 15px;
                        margin-bottom: 10px;
                    }
                    
                    .edr-process-tree-filter select {
                        margin-left: 5px;
                        padding: 5px;
                        border-radius: 4px;
                        border: 1px solid #ccc;
                        min-width: 150px;
                    }
                    
                    .theme-dark .edr-process-tree-filter select {
                        background-color: #444;
                        color: #e0e0e0;
                        border-color: #555;
                    }
                    
                    .edr-process-tree-svg-container {
                        position: relative;
                        overflow: hidden;
                        border-radius: 4px;
                    }
                    
                    .theme-dark .edr-process-tree-svg-container {
                        background-color: #1e1e1e;
                    }
                    
                    .theme-light .edr-process-tree-svg-container {
                        background-color: #fff;
                        border: 1px solid #ddd;
                    }
                    
                    .edr-process-tree-reset-zoom {
                        position: absolute;
                        top: 10px;
                        right: 10px;
                        padding: 5px 10px;
                        border-radius: 4px;
                        border: 1px solid rgba(255, 255, 255, 0.2);
                        background-color: rgba(0, 0, 0, 0.5);
                        color: white;
                        cursor: pointer;
                        font-size: 12px;
                        z-index: 10;
                    }
                    
                    .theme-light .edr-process-tree-reset-zoom {
                        background-color: rgba(0, 0, 0, 0.1);
                        color: #333;
                        border-color: rgba(0, 0, 0, 0.1);
                    }
                    
                    .edr-process-tree-tooltip {
                        position: absolute;
                        padding: 10px;
                        border-radius: 4px;
                        pointer-events: none;
                        max-width: 300px;
                        z-index: 100;
                        font-size: 12px;
                        word-wrap: break-word;
                        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
                    }
                    
                    .theme-dark .edr-process-tree-tooltip {
                        background-color: rgba(0, 0, 0, 0.8);
                        color: white;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                    }
                    
                    .theme-light .edr-process-tree-tooltip {
                        background-color: rgba(255, 255, 255, 0.95);
                        color: #333;
                        border: 1px solid rgba(0, 0, 0, 0.1);
                    }
                    
                    .edr-process-tree-tooltip-title {
                        font-weight: bold;
                        margin-bottom: 5px;
                    }
                    
                    .edr-process-tree-tooltip-section {
                        margin-top: 5px;
                    }
                    
                    .edr-process-tree-tooltip-label {
                        font-weight: bold;
                        color: #999;
                    }
                    
                    .theme-dark .node circle {
                        fill: #555;
                        stroke: #333;
                    }
                    
                    .theme-light .node circle {
                        fill: #999;
                        stroke: #fff;
                    }
                    
                    .node text {
                        font-size: 12px;
                    }
                    
                    .theme-dark .node text {
                        fill: #e0e0e0;
                    }
                    
                    .theme-light .node text {
                        fill: #333;
                    }
                    
                    .link {
                        fill: none;
                        stroke-width: 1.5px;
                    }
                    
                    .theme-dark .link {
                        stroke: #555;
                    }
                    
                    .theme-light .link {
                        stroke: #bbb;
                    }
                    
                    .node-toggle {
                        cursor: pointer;
                        font-size: 16px;
                        font-weight: bold;
                    }
                    
                    .node-toggle.collapsed {
                        fill: #4CAF50;
                    }
                    
                    .node-toggle.expanded {
                        fill: #F44336;
                    }
                    
                    .node.highlight circle {
                        stroke: #F82B60;
                        stroke-width: 3px;
                    }
                    
                    .node.highlight text {
                        font-weight: bold;
                    }
                    
                    .node.filtered {
                        opacity: 0.3;
                    }
                    
                    .node.hidden {
                        display: none;
                    }
                    
                    .node.selected circle {
                        stroke: #2196F3;
                        stroke-width: 3px;
                    }
                    
                    .details-panel {
                        position: absolute;
                        right: 10px;
                        bottom: 10px;
                        padding: 10px;
                        border-radius: 4px;
                        max-width: 300px;
                        max-height: 200px;
                        overflow-y: auto;
                        font-size: 12px;
                        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
                        z-index: 10;
                    }
                    
                    .theme-dark .details-panel {
                        background-color: rgba(30, 30, 30, 0.9);
                        border: 1px solid rgba(255, 255, 255, 0.1);
                    }
                    
                    .theme-light .details-panel {
                        background-color: rgba(255, 255, 255, 0.95);
                        border: 1px solid rgba(0, 0, 0, 0.1);
                    }
                    
                    .details-panel-title {
                        font-weight: bold;
                        margin-bottom: 5px;
                    }
                    
                    .details-panel-close {
                        position: absolute;
                        top: 5px;
                        right: 5px;
                        cursor: pointer;
                        font-size: 14px;
                    }
                    
                    @media (max-width: 768px) {
                        .edr-process-tree-toolbar,
                        .edr-process-tree-filters {
                            flex-direction: column;
                            gap: 5px;
                        }
                        
                        .edr-process-tree-filter {
                            margin-bottom: 5px;
                        }
                    }
                `;
                document.head.appendChild(style);
            }
        },
        
        /**
         * Update the visualization with new data
         * @param {Array} data - Data from Splunk search
         */
        updateData: function(data) {
            // Clear existing visualization
            this.svg.selectAll('*').remove();
            
            // Add back the background rect
            this.svg.append('rect')
                .attr('class', 'background')
                .attr('width', '100%')
                .attr('height', '100%')
                .attr('fill', 'transparent');
                
            // Process the data into a hierarchical structure
            const rootProcesses = this._buildProcessHierarchy(data);
            
            // Store the data
            this.data = rootProcesses;
            this.filteredData = rootProcesses;
            
            // Reset state
            this.expandedNodes = new Set();
            this.selectedNode = null;
            this.searchTerm = '';
            
            // Initialize collapsed/expanded state
            this._initializeNodeState(rootProcesses);
            
            // Update provider filter options based on data
            this._updateProviderFilterOptions(data);
            
            // Adjust height based on data
            this._adjustHeight();
            
            // Draw the tree
            this._drawTree();
        },
        
        /**
         * Adjust SVG height based on data
         */
        _adjustHeight: function() {
            // Count total number of visible nodes
            const nodeCount = this._countVisibleNodes(this.filteredData);
            
            // Calculate height based on node count and layout
            let height = this.settings.minHeight;
            
            if (this.settings.treeLayout === 'horizontal') {
                height = Math.min(
                    this.settings.maxHeight,
                    Math.max(this.settings.minHeight, nodeCount * 30)
                );
            } else {
                // For vertical layout, width becomes the limiting factor
                // We'll still adjust height to fit tree better
                height = Math.min(
                    this.settings.maxHeight,
                    Math.max(this.settings.minHeight, nodeCount * 15)
                );
            }
            
            // Update SVG height
            d3.select(this.el).select('.edr-process-tree-svg-container svg')
                .attr('height', height);
        },
        
        /**
         * Count visible nodes based on expanded state
         * @param {Array} nodes - Tree nodes
         * @param {number} depth - Current depth
         * @returns {number} - Count of visible nodes
         */
        _countVisibleNodes: function(nodes, depth = 0) {
            if (!nodes) return 0;
            
            let count = 0;
            
            for (let i = 0; i < nodes.length; i++) {
                const node = nodes[i];
                
                // Count this node
                count++;
                
                // Count children if expanded
                if (node.children && this.expandedNodes.has(node.id)) {
                    count += this._countVisibleNodes(node.children, depth + 1);
                }
            }
            
            return count;
        },
        
        /**
         * Initialize node state (expanded/collapsed)
         * @param {Array} nodes - Tree nodes
         * @param {number} depth - Current depth
         */
        _initializeNodeState: function(nodes, depth = 0) {
            if (!nodes) return;
            
            for (let i = 0; i < nodes.length; i++) {
                const node = nodes[i];
                
                // Expand nodes up to the initial collapse depth
                if (depth < this.settings.initialCollapseDepth) {
                    this.expandedNodes.add(node.id);
                }
                
                // Process children
                if (node.children) {
                    this._initializeNodeState(node.children, depth + 1);
                }
            }
        },
        
        /**
         * Update provider filter options based on data
         * @param {Array} data - Raw data
         */
        _updateProviderFilterOptions: function(data) {
            // Get unique providers
            const providers = new Set();
            data.forEach(row => {
                const provider = this._getProviderFromRow(row);
                if (provider) {
                    providers.add(provider.toLowerCase());
                }
            });
            
            // Clear existing options except "All"
            const $select = this.$providerFilter.find('select');
            $select.find('option:not([value="all"])').remove();
            
            // Add provider options
            providers.forEach(provider => {
                const displayName = provider.charAt(0).toUpperCase() + provider.slice(1);
                $select.append(`<option value="${provider}">${displayName}</option>`);
            });
        },
        
        /**
         * Get provider from data row
         * @param {Object} row - Data row
         * @returns {string} - Provider name
         */
        _getProviderFromRow: function(row) {
            return row.edr_provider || row.provider || '';
        },
        
        /**
         * Draw the process tree
         */
        _drawTree: function() {
            // Clear previous tree
            this.svg.selectAll('.link, .node').remove();
            
            if (!this.filteredData || this.filteredData.length === 0) {
                // No data, show empty message
                this.svg.append('text')
                    .attr('class', 'empty-message')
                    .attr('x', 20)
                    .attr('y', 30)
                    .text('No process data available');
                return;
            }
            
            // Set up the tree layout
            const treeLayout = d3.tree()
                .nodeSize(this.settings.treeLayout === 'horizontal' 
                    ? [this.settings.verticalSpacing, this.settings.horizontalSpacing]
                    : [this.settings.horizontalSpacing, this.settings.verticalSpacing])
                .separation((a, b) => {
                    return a.parent === b.parent ? 1.2 : 2;
                });
                
            // Draw each process tree
            let offset = 0;
            this.filteredData.forEach(root => {
                // Clone the root to avoid modifying original data
                const rootCopy = this._preprocessNode(root);
                
                // Create hierarchy
                const hierarchyRoot = d3.hierarchy(rootCopy);
                
                // Apply the tree layout
                const treeData = treeLayout(hierarchyRoot);
                
                // Draw the tree with proper orientation
                if (this.settings.treeLayout === 'horizontal') {
                    this._drawHorizontalTree(treeData, offset);
                    // Update offset for next tree
                    offset += this._getTreeHeight(treeData) + this.settings.verticalSpacing * 3;
                } else {
                    this._drawVerticalTree(treeData, offset);
                    // Update offset for next tree
                    offset += this._getTreeWidth(treeData) + this.settings.horizontalSpacing * 3;
                }
            });
            
            // Center the visualization
            this._centerVisualization();
        },
        
        /**
         * Preprocess node to handle collapsed state
         * @param {Object} node - Node to preprocess
         * @returns {Object} - Processed node
         */
        _preprocessNode: function(node) {
            // Clone the node to avoid modifying original
            const nodeCopy = Object.assign({}, node);
            
            // If node has children and is not expanded, set _children instead
            if (nodeCopy.children && !this.expandedNodes.has(nodeCopy.id)) {
                nodeCopy._children = nodeCopy.children.map(child => this._preprocessNode(child));
                delete nodeCopy.children;
            } else if (nodeCopy.children) {
                // Process children recursively
                nodeCopy.children = nodeCopy.children.map(child => this._preprocessNode(child));
            }
            
            return nodeCopy;
        },
        
        /**
         * Draw horizontal tree layout
         * @param {Object} treeData - D3 hierarchy data
         * @param {number} yOffset - Vertical offset
         */
        _drawHorizontalTree: function(treeData, yOffset) {
            const self = this;
            
            // Create links
            this.svg.selectAll('.link')
                .data(treeData.links())
                .enter()
                .append('path')
                .attr('class', 'link')
                .attr('d', d => {
                    // Draw curved links between nodes
                    return `M${d.source.y},${d.source.x + yOffset}
                            C${(d.source.y + d.target.y) / 2},${d.source.x + yOffset}
                             ${(d.source.y + d.target.y) / 2},${d.target.x + yOffset}
                             ${d.target.y},${d.target.x + yOffset}`;
                });
                
            // Create node groups
            const nodeGroups = this.svg.selectAll('.node')
                .data(treeData.descendants())
                .enter()
                .append('g')
                .attr('class', d => {
                    let classes = 'node';
                    
                    if (this.searchTerm && this._nodeMatchesSearch(d.data)) {
                        classes += ' highlight';
                    }
                    
                    if (this.selectedNode === d.data.id) {
                        classes += ' selected';
                    }
                    
                    return classes;
                })
                .attr('transform', d => `translate(${d.y},${d.x + yOffset})`)
                .on('click', function(event, d) {
                    self._handleNodeClick(d, this);
                });
                
            // Add node circles
            nodeGroups.append('circle')
                .attr('r', 6)
                .style('fill', d => this._getNodeColor(d.data))
                .style('cursor', 'pointer')
                .on('mouseover', function(event, d) {
                    self._handleNodeMouseOver(event, d);
                })
                .on('mouseout', function() {
                    self._handleNodeMouseOut();
                });
                
            // Add expand/collapse toggle for nodes with children
            nodeGroups.each(function(d) {
                const node = d3.select(this);
                const data = d.data;
                
                // Check if node has children (either visible or hidden)
                if (data.children || data._children) {
                    node.append('text')
                        .attr('class', 'node-toggle ' + (data.children ? 'expanded' : 'collapsed'))
                        .attr('dy', '0.32em')
                        .attr('x', -18)
                        .attr('text-anchor', 'middle')
                        .text(data.children ? '−' : '+')
                        .on('click', function(event) {
                            event.stopPropagation();
                            self._toggleNode(data);
                        });
                }
            });
                
            // Add text labels
            nodeGroups.append('text')
                .attr('dy', '.35em')
                .attr('x', d => d.data.children ? -10 : 10)
                .style('text-anchor', d => d.data.children ? 'end' : 'start')
                .text(d => d.data.name)
                .on('mouseover', function(event, d) {
                    self._handleNodeMouseOver(event, d);
                })
                .on('mouseout', function() {
                    self._handleNodeMouseOut();
                });
                
            // Add command line text if enabled
            if (this.settings.showCommandLine) {
                nodeGroups.append('text')
                    .attr('dy', '1.5em')
                    .attr('x', d => d.data.children ? -10 : 10)
                    .style('text-anchor', d => d.data.children ? 'end' : 'start')
                    .style('font-size', '10px')
                    .style('opacity', 0.7)
                    .text(d => {
                        // Truncate command line if too long
                        if (d.data.commandLine && d.data.commandLine.length > 40) {
                            return d.data.commandLine.substring(0, 40) + '...';
                        }
                        return d.data.commandLine || '';
                    });
            }
        },
        
        /**
         * Draw vertical tree layout
         * @param {Object} treeData - D3 hierarchy data
         * @param {number} xOffset - Horizontal offset
         */
        _drawVerticalTree: function(treeData, xOffset) {
            const self = this;
            
            // Create links
            this.svg.selectAll('.link')
                .data(treeData.links())
                .enter()
                .append('path')
                .attr('class', 'link')
                .attr('d', d => {
                    // Draw curved links between nodes
                    return `M${d.source.x + xOffset},${d.source.y}
                            C${d.source.x + xOffset},${(d.source.y + d.target.y) / 2}
                             ${d.target.x + xOffset},${(d.source.y + d.target.y) / 2}
                             ${d.target.x + xOffset},${d.target.y}`;
                });
                
            // Create node groups
            const nodeGroups = this.svg.selectAll('.node')
                .data(treeData.descendants())
                .enter()
                .append('g')
                .attr('class', d => {
                    let classes = 'node';
                    
                    if (this.searchTerm && this._nodeMatchesSearch(d.data)) {
                        classes += ' highlight';
                    }
                    
                    if (this.selectedNode === d.data.id) {
                        classes += ' selected';
                    }
                    
                    return classes;
                })
                .attr('transform', d => `translate(${d.x + xOffset},${d.y})`)
                .on('click', function(event, d) {
                    self._handleNodeClick(d, this);
                });
                
            // Add node circles
            nodeGroups.append('circle')
                .attr('r', 6)
                .style('fill', d => this._getNodeColor(d.data))
                .style('cursor', 'pointer')
                .on('mouseover', function(event, d) {
                    self._handleNodeMouseOver(event, d);
                })
                .on('mouseout', function() {
                    self._handleNodeMouseOut();
                });
                
            // Add expand/collapse toggle for nodes with children
            nodeGroups.each(function(d) {
                const node = d3.select(this);
                const data = d.data;
                
                // Check if node has children (either visible or hidden)
                if (data.children || data._children) {
                    node.append('text')
                        .attr('class', 'node-toggle ' + (data.children ? 'expanded' : 'collapsed'))
                        .attr('dy', '-1em')
                        .attr('text-anchor', 'middle')
                        .text(data.children ? '−' : '+')
                        .on('click', function(event) {
                            event.stopPropagation();
                            self._toggleNode(data);
                        });
                }
            });
                
            // Add text labels
            nodeGroups.append('text')
                .attr('dy', '-.5em')
                .attr('x', 0)
                .attr('text-anchor', 'middle')
                .text(d => d.data.name)
                .on('mouseover', function(event, d) {
                    self._handleNodeMouseOver(event, d);
                })
                .on('mouseout', function() {
                    self._handleNodeMouseOut();
                });
                
            // Add command line text if enabled
            if (this.settings.showCommandLine) {
                nodeGroups.append('text')
                    .attr('dy', '1em')
                    .attr('x', 0)
                    .style('text-anchor', 'middle')
                    .style('font-size', '10px')
                    .style('opacity', 0.7)
                    .text(d => {
                        // Truncate command line if too long
                        if (d.data.commandLine && d.data.commandLine.length > 30) {
                            return d.data.commandLine.substring(0, 30) + '...';
                        }
                        return d.data.commandLine || '';
                    });
            }
        },
        
        /**
         * Get node color based on settings
         * @param {Object} node - Node data
         * @returns {string} - Color for the node
         */
        _getNodeColor: function(node) {
            if (this.settings.colorByProvider) {
                return this.providerColors[node.provider] || this.providerColors.default;
            } else {
                return this.statusColors(node.status || 'normal');
            }
        },
        
        /**
         * Update node colors when color mode changes
         */
        _updateNodeColors: function() {
            this.svg.selectAll('.node circle')
                .style('fill', d => this._getNodeColor(d.data));
        },
        
        /**
         * Handle node click
         * @param {Object} d - Node data
         * @param {Element} element - DOM element
         */
        _handleNodeClick: function(d, element) {
            // Select this node
            this.selectedNode = d.data.id;
            
            // Update selection styling
            this.svg.selectAll('.node').classed('selected', false);
            d3.select(element).classed('selected', true);
            
            // Show details panel
            this._showDetailsPanel(d.data);
        },
        
        /**
         * Show details panel for selected node
         * @param {Object} nodeData - Node data
         */
        _showDetailsPanel: function(nodeData) {
            // Remove existing panel
            d3.select(this.el).select('.details-panel').remove();
            
            // Create details panel
            const panel = d3.select(this.el).select('.edr-process-tree-svg-container')
                .append('div')
                .attr('class', 'details-panel')
                .style('opacity', 0);
                
            // Add title
            panel.append('div')
                .attr('class', 'details-panel-title')
                .text(nodeData.name);
                
            // Add close button
            panel.append('div')
                .attr('class', 'details-panel-close')
                .html('&times;')
                .on('click', () => {
                    panel.transition()
                        .duration(300)
                        .style('opacity', 0)
                        .on('end', function() {
                            d3.select(this).remove();
                        });
                        
                    // Clear selection
                    this.selectedNode = null;
                    this.svg.selectAll('.node').classed('selected', false);
                });
                
            // Add details content
            const content = panel.append('div')
                .attr('class', 'details-panel-content');
                
            // Add hostname
            if (nodeData.hostname) {
                content.append('div')
                    .attr('class', 'details-panel-item')
                    .html(`<span class="details-panel-label">Host:</span> ${nodeData.hostname}`);
            }
            
            // Add provider
            if (nodeData.provider) {
                content.append('div')
                    .attr('class', 'details-panel-item')
                    .html(`<span class="details-panel-label">Provider:</span> ${nodeData.provider}`);
            }
            
            // Add status
            if (nodeData.status) {
                content.append('div')
                    .attr('class', 'details-panel-item')
                    .html(`<span class="details-panel-label">Status:</span> ${nodeData.status}`);
            }
            
            // Add command line
            if (nodeData.commandLine) {
                content.append('div')
                    .attr('class', 'details-panel-item')
                    .html(`<span class="details-panel-label">Command:</span> ${nodeData.commandLine}`);
            }
            
            // Add SHA256
            if (nodeData.sha256) {
                content.append('div')
                    .attr('class', 'details-panel-item')
                    .html(`<span class="details-panel-label">SHA256:</span> ${nodeData.sha256}`);
            }
            
            // Add timestamps if available
            if (nodeData.data && nodeData.data.timestamp) {
                content.append('div')
                    .attr('class', 'details-panel-item')
                    .html(`<span class="details-panel-label">Timestamp:</span> ${nodeData.data.timestamp}`);
            }
            
            // Show panel with animation
            panel.transition()
                .duration(300)
                .style('opacity', 1);
        },
        
        /**
         * Handle node mouseover
         * @param {Event} event - Mouse event
         * @param {Object} d - Node data
         */
        _handleNodeMouseOver: function(event, d) {
            // Show tooltip
            this.tooltip.transition()
                .duration(200)
                .style('opacity', 0.9);
                
            // Build tooltip content
            let content = `<div class="edr-process-tree-tooltip-title">${d.data.name}</div>`;
            
            if (d.data.hostname) {
                content += `<div class="edr-process-tree-tooltip-section">
                    <span class="edr-process-tree-tooltip-label">Host:</span> ${d.data.hostname}
                </div>`;
            }
            
            if (d.data.provider) {
                content += `<div class="edr-process-tree-tooltip-section">
                    <span class="edr-process-tree-tooltip-label">Provider:</span> ${d.data.provider}
                </div>`;
            }
            
            if (d.data.commandLine) {
                content += `<div class="edr-process-tree-tooltip-section">
                    <span class="edr-process-tree-tooltip-label">Command:</span> ${d.data.commandLine}
                </div>`;
            }
            
            if (d.data.status) {
                content += `<div class="edr-process-tree-tooltip-section">
                    <span class="edr-process-tree-tooltip-label">Status:</span> ${d.data.status}
                </div>`;
            }
            
            this.tooltip.html(content)
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 28) + 'px');
        },
        
        /**
         * Handle node mouseout
         */
        _handleNodeMouseOut: function() {
            // Hide tooltip
            this.tooltip.transition()
                .duration(500)
                .style('opacity', 0);
        },
        
        /**
         * Toggle node expansion state
         * @param {Object} node - Node to toggle
         */
        _toggleNode: function(node) {
            if (node.children) {
                // Collapse
                node._children = node.children;
                node.children = null;
                this.expandedNodes.delete(node.id);
            } else if (node._children) {
                // Expand
                node.children = node._children;
                node._children = null;
                this.expandedNodes.add(node.id);
            }
            
            // Redraw the tree
            this._redrawTree();
        },
        
        /**
         * Expand all nodes
         */
        _expandAll: function() {
            const self = this;
            
            function expand(nodes) {
                if (!nodes) return;
                
                for (let i = 0; i < nodes.length; i++) {
                    const node = nodes[i];
                    
                    // Add to expanded set
                    self.expandedNodes.add(node.id);
                    
                    // Expand children recursively
                    if (node.children) {
                        expand(node.children);
                    } else if (node._children) {
                        expand(node._children);
                    }
                }
            }
            
            // Expand all nodes
            expand(this.filteredData);
            
            // Redraw the tree
            this._redrawTree();
        },
        
        /**
         * Collapse all nodes
         */
        _collapseAll: function() {
            // Clear all expanded nodes except root level
            this.expandedNodes.clear();
            
            // Add root level nodes
            this.filteredData.forEach(root => {
                this.expandedNodes.add(root.id);
            });
            
            // Redraw the tree
            this._redrawTree();
        },
        
        /**
         * Redraw the tree
         */
        _redrawTree: function() {
            // Adjust height based on expanded nodes
            this._adjustHeight();
            
            // Redraw
            this._drawTree();
        },
        
        /**
         * Reset zoom
         */
        _resetZoom: function() {
            d3.select(this.el).select('.edr-process-tree-svg-container svg')
                .transition()
                .duration(750)
                .call(this.zoom.transform, d3.zoomIdentity);
        },
        
        /**
         * Center the visualization
         */
        _centerVisualization: function() {
            // Get SVG dimensions
            const svg = d3.select(this.el).select('.edr-process-tree-svg-container svg');
            const width = parseInt(svg.style('width'), 10);
            const height = parseInt(svg.style('height'), 10);
            
            // Center the visualization
            const transform = d3.zoomIdentity.translate(width / 4, height / 2);
            
            svg.transition()
                .duration(750)
                .call(this.zoom.transform, transform);
        },
        
        /**
         * Calculate tree height
         * @param {Object} treeData - D3 hierarchy data
         * @returns {number} - Tree height
         */
        _getTreeHeight: function(treeData) {
            let minX = Infinity;
            let maxX = -Infinity;
            
            treeData.descendants().forEach(node => {
                minX = Math.min(minX, node.x);
                maxX = Math.max(maxX, node.x);
            });
            
            return maxX - minX + 50; // Add padding
        },
        
        /**
         * Calculate tree width
         * @param {Object} treeData - D3 hierarchy data
         * @returns {number} - Tree width
         */
        _getTreeWidth: function(treeData) {
            let minY = Infinity;
            let maxY = -Infinity;
            
            treeData.descendants().forEach(node => {
                minY = Math.min(minY, node.x);
                maxY = Math.max(maxY, node.x);
            });
            
            return maxY - minY + 50; // Add padding
        },
        
        /**
         * Handle search
         * @param {string} term - Search term
         */
        _handleSearch: function(term) {
            this.searchTerm = term.toLowerCase();
            
            // Update node highlighting
            this.svg.selectAll('.node')
                .classed('highlight', d => term && this._nodeMatchesSearch(d.data));
                
            // If search term is not empty, expand nodes to show matches
            if (term) {
                this._expandToShowMatches(this.filteredData);
                this._redrawTree();
            }
        },
        
        /**
         * Check if node matches search term
         * @param {Object} node - Node data
         * @returns {boolean} - True if node matches search
         */
        _nodeMatchesSearch: function(node) {
            if (!this.searchTerm) return false;
            
            // Check node name
            if (node.name && node.name.toLowerCase().includes(this.searchTerm)) {
                return true;
            }
            
            // Check command line
            if (node.commandLine && node.commandLine.toLowerCase().includes(this.searchTerm)) {
                return true;
            }
            
            // Check hostname
            if (node.hostname && node.hostname.toLowerCase().includes(this.searchTerm)) {
                return true;
            }
            
            return false;
        },
        
        /**
         * Expand nodes to show search matches
         * @param {Array} nodes - Tree nodes
         * @returns {boolean} - True if any node matches
         */
        _expandToShowMatches: function(nodes) {
            if (!nodes) return false;
            
            let hasMatch = false;
            
            for (let i = 0; i < nodes.length; i++) {
                const node = nodes[i];
                
                // Check if this node matches
                const nodeMatches = this._nodeMatchesSearch(node);
                
                // Check if any children match
                let childrenMatch = false;
                if (node.children) {
                    childrenMatch = this._expandToShowMatches(node.children);
                } else if (node._children) {
                    childrenMatch = this._expandToShowMatches(node._children);
                    
                    // If any children match, expand this node
                    if (childrenMatch) {
                        this.expandedNodes.add(node.id);
                    }
                }
                
                // This subtree has a match if this node or any children match
                hasMatch = hasMatch || nodeMatches || childrenMatch;
            }
            
            return hasMatch;
        },
        
        /**
         * Apply filters to the data
         */
        _applyFilters: function() {
            // Get filter values
            const providers = this._getSelectedValues(this.$providerFilter.find('select'));
            const statuses = this._getSelectedValues(this.$statusFilter.find('select'));
            
            // Check if we're filtering by provider
            const filterProviders = providers.indexOf('all') === -1;
            
            // Check if we're filtering by status
            const filterStatuses = statuses.indexOf('all') === -1;
            
            // Apply filters
            if (filterProviders || filterStatuses) {
                this.filteredData = this._filterData(this.data, provider => {
                    // Check provider filter
                    if (filterProviders && providers.indexOf(provider.provider.toLowerCase()) === -1) {
                        return false;
                    }
                    
                    // Check status filter
                    if (filterStatuses && statuses.indexOf(provider.status || 'normal') === -1) {
                        return false;
                    }
                    
                    return true;
                });
            } else {
                // No filters, use all data
                this.filteredData = this.data;
            }
            
            // Redraw with filtered data
            this._redrawTree();
        },
        
        /**
         * Get selected values from a multi-select
         * @param {jQuery} $select - Select element
         * @returns {Array} - Selected values
         */
        _getSelectedValues: function($select) {
            const values = [];
            $select.find('option:selected').each(function() {
                values.push($(this).val());
            });
            return values;
        },
        
        /**
         * Filter data based on a predicate
         * @param {Array} nodes - Tree nodes
         * @param {Function} predicate - Filter predicate
         * @returns {Array} - Filtered nodes
         */
        _filterData: function(nodes, predicate) {
            if (!nodes) return [];
            
            const result = [];
            
            for (let i = 0; i < nodes.length; i++) {
                const node = nodes[i];
                
                // Clone the node
                const nodeCopy = Object.assign({}, node);
                
                // Filter children
                if (nodeCopy.children) {
                    nodeCopy.children = this._filterData(nodeCopy.children, predicate);
                }
                
                // Add node if it passes the predicate or has passing children
                if (predicate(nodeCopy) || (nodeCopy.children && nodeCopy.children.length > 0)) {
                    result.push(nodeCopy);
                }
            }
            
            return result;
        },
        
        /**
         * Build process hierarchy from flat data
         * @param {Array} data - Flat process data
         * @returns {Array} - Root process objects
         */
        _buildProcessHierarchy: function(data) {
            // Create process map by ID
            const processMap = {};
            
            // First pass: create nodes for all processes
            data.forEach(row => {
                const processData = this._normalizeProcessData(row);
                
                if (processData.process_id) {
                    // Create or update process node
                    processMap[processData.process_id] = {
                        id: processData.process_id,
                        name: processData.process_name || 'Unknown',
                        commandLine: processData.command_line || '',
                        hostname: processData.hostname || '',
                        provider: processData.provider.toLowerCase() || 'unknown',
                        status: processData.status || 'normal',
                        sha256: processData.sha256 || '',
                        children: [],
                        data: processData
                    };
                }
            });
            
            // Second pass: build parent-child relationships
            const rootProcesses = [];
            
            for (const id in processMap) {
                const process = processMap[id];
                const parentId = process.data.parent_process_id;
                
                if (parentId && processMap[parentId]) {
                    // Add as child to parent
                    processMap[parentId].children.push(process);
                    process.parent = processMap[parentId];
                } else {
                    // No parent found, add as root
                    rootProcesses.push(process);
                }
            }
            
            return rootProcesses;
        },
        
        /**
         * Normalize process data from different providers
         * @param {Object} row - Raw process data
         * @returns {Object} - Normalized process data
         */
        _normalizeProcessData: function(row) {
            const provider = row.edr_provider || row.provider || '';
            
            let process = {
                provider: provider.toLowerCase(),
                hostname: row.edr_hostname || row.hostname || '',
            };
            
            // Extract fields based on provider
            if (provider.toLowerCase() === 'crowdstrike') {
                process.process_id = row.process_id || row.ProcessId || '';
                process.process_name = row.process_name || row.FileName || '';
                process.command_line = row.command_line || row.CommandLine || '';
                process.parent_process_id = row.parent_process_id || row.ParentProcessId || '';
                process.parent_process_name = row.parent_process_name || row.ParentBaseFileName || '';
                process.sha256 = row.sha256 || '';
                process.status = row.state || 'normal';
                process.timestamp = row.timestamp || '';
                
            } else if (provider.toLowerCase() === 'sentinelone') {
                process.process_id = row.id || row.processId || '';
                process.process_name = row.name || row.processName || '';
                process.command_line = row.commandLine || '';
                process.parent_process_id = row.parentId || row.parentProcessId || '';
                process.parent_process_name = row.parentName || '';
                process.sha256 = row.sha256 || '';
                process.status = row.processState || 'normal';
                process.timestamp = row.createdAt || '';
                
            } else if (provider.toLowerCase() === 'defender') {
                process.process_id = row.ProcessId || row.InitiatingProcessId || '';
                process.process_name = row.FileName || row.InitiatingProcessFileName || '';
                process.command_line = row.ProcessCommandLine || row.InitiatingProcessCommandLine || '';
                process.parent_process_id = row.InitiatingProcessParentId || '';
                process.parent_process_name = row.InitiatingProcessParentFileName || '';
                process.sha256 = row.SHA256 || '';
                process.status = 'normal';
                process.timestamp = row.TimeGenerated || '';
            }
            
            // Handle edr_ prefixed fields (from custom command output)
            if (!process.process_id && row.edr_process_id) {
                process.process_id = row.edr_process_id;
            }
            
            if (!process.process_name && row.edr_process_name) {
                process.process_name = row.edr_process_name;
            }
            
            if (!process.command_line && row.edr_command_line) {
                process.command_line = row.edr_command_line;
            }
            
            if (!process.parent_process_id && row.edr_parent_process_id) {
                process.parent_process_id = row.edr_parent_process_id;
            }
            
            if (!process.sha256 && row.edr_sha256) {
                process.sha256 = row.edr_sha256;
            }
            
            if (!process.status && row.edr_status) {
                process.status = row.edr_status;
            }
            
            // Add timestamp from various possible fields
            if (!process.timestamp) {
                process.timestamp = row.edr_timestamp || row.time || row._time || '';
            }
            
            // Ensure process has some name
            if (!process.process_name) {
                if (process.command_line) {
                    // Extract executable name from command line
                    const match = process.command_line.match(/([^\\\/]+)(?:\.exe)?(?:\s|$)/i);
                    if (match) {
                        process.process_name = match[1];
                    } else {
                        process.process_name = 'Unknown';
                    }
                } else {
                    process.process_name = 'Unknown';
                }
            }
            
            return process;
        }
    };
    
    // Register the visualization with Splunk
    mvc.Components.get('processTree') || mvc.Components.register('processTree', ProcessTreeViz);
});
