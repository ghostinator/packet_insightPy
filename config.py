#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import yaml
import json
from pathlib import Path

class PacketInsightConfig:
    """Configuration manager for Packet Insight"""
    
    # Default configuration values
    DEFAULT_CONFIG = {
        # Analysis thresholds
        'retransmission_threshold': 0.05,  # 5% retransmission rate threshold
        'high_jitter_threshold': 0.1,      # 100ms jitter threshold
        'syn_delay_threshold': 0.5,        # 500ms SYN delay threshold
        'dns_timeout_threshold': 1.0,      # 1s DNS response time threshold
        
        # Live capture settings
        'rolling_capture_size_mb': 100,    # Start new capture file after 100MB
        'rolling_capture_interval_min': 15, # Start new capture file every 15 minutes
        'enable_realtime_alerts': True,    # Show alerts in real-time during live capture
        'default_capture_duration': 60,    # Default capture duration in seconds
        
        # Output settings
        'default_output_format': 'text',   # Default output format (text, json, csv, html)
        'default_output_dir': 'reports',   # Default directory for saving reports
        
        # Advanced settings
        'packet_sample_rate': 1,           # Process every Nth packet (1 = all packets)
        'max_packets_in_memory': 10000,    # Maximum packets to keep in memory
        'enable_experimental_features': False, # Enable experimental features
    }
    
    def __init__(self, config_dict=None):
        """Initialize configuration with optional custom values"""
        self.config = self.DEFAULT_CONFIG.copy()
        if config_dict:
            self.config.update(config_dict)
    
    @classmethod
    def from_file(cls, config_path=None):
        """Load configuration from file with fallbacks"""
        # Try user-specified path first
        if config_path and os.path.exists(config_path):
            return cls._load_from_path(config_path)
        
        # Try standard locations
        standard_paths = [
            'packet_insight.yaml',  # Current directory
            'packet_insight.yml',
            os.path.expanduser('~/.config/packet_insight.yaml'),  # User config directory
            os.path.expanduser('~/.packet_insight.yaml'),  # User home
            '/etc/packet_insight.yaml',  # System-wide (Linux/macOS)
        ]
        
        for path in standard_paths:
            if os.path.exists(path):
                return cls._load_from_path(path)
        
        # No config found, use defaults
        print("[i] No configuration file found. Using defaults.")
        return cls()
    
    @classmethod
    def _load_from_path(cls, path):
        """Load configuration from a specific path"""
        try:
            with open(path, 'r') as f:
                if path.endswith(('.yaml', '.yml')):
                    config_dict = yaml.safe_load(f)
                elif path.endswith('.json'):
                    config_dict = json.load(f)
                else:
                    raise ValueError(f"Unsupported config format: {path}")
                
                print(f"[i] Loaded configuration from {path}")
                return cls(config_dict)
        except Exception as e:
            print(f"[!] Error loading configuration from {path}: {e}")
            print("[i] Using default configuration")
            return cls()
    
    def save_to_file(self, path):
        """Save current configuration to file"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            
            # Determine format based on extension
            if path.endswith(('.yaml', '.yml')):
                with open(path, 'w') as f:
                    yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            elif path.endswith('.json'):
                with open(path, 'w') as f:
                    json.dump(self.config, f, indent=2)
            else:
                # Default to YAML if no recognized extension
                with open(path, 'w') as f:
                    yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            
            return True
        except Exception as e:
            print(f"[!] Error saving configuration to {path}: {e}")
            return False
    
    def get(self, key, default=None):
        """Get configuration value with optional default"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """Set configuration value"""
        self.config[key] = value
    
    def update(self, config_dict):
        """Update multiple configuration values"""
        self.config.update(config_dict)
    
    def __getitem__(self, key):
        """Allow dictionary-like access to configuration"""
        return self.config[key]
    
    def __setitem__(self, key, value):
        """Allow dictionary-like setting of configuration"""
        self.config[key] = value
        
    def __getattr__(self, name):
        """Allow attribute-style access to configuration"""
        # Convert attribute name to lowercase for case-insensitive lookup
        for key in self.config:
            if key.lower() == name.lower():
                return self.config[key]
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
    
    def __setattr__(self, name, value):
        """Allow attribute-style setting of configuration"""
        if name == 'config':
            # Special case for the config dictionary itself
            super().__setattr__(name, value)
        else:
            # For other attributes, store in the config dictionary
            self.config[name] = value

# Example usage
if __name__ == "__main__":
    # Export default configuration
    if len(sys.argv) > 1:
        config = PacketInsightConfig()
        config.save_to_file(sys.argv[1])
        print(f"Default configuration exported to {sys.argv[1]}")
    else:
        print("Usage: python config.py <output_file>")