"""Monkey patches for pyshark to prevent event loop issues"""
import logging

def apply_patches():
    """Apply monkey patches to pyshark to prevent event loop issues"""
    try:
        # Import pyshark
        import pyshark
        from pyshark.capture.capture import Capture
        
        # Save the original __del__ method
        original_del = Capture.__del__
        
        # Create a safe __del__ method that doesn't use the event loop
        def safe_del(self):
            try:
                # Skip the event loop cleanup
                pass
            except Exception:
                pass
        
        # Replace the __del__ method
        Capture.__del__ = safe_del
        
        # Log the monkey patching
        logging.info("Monkey patched pyshark.capture.Capture.__del__ to prevent event loop issues")
        return True
    except Exception as e:
        logging.warning(f"Failed to monkey patch pyshark: {e}")
        return False