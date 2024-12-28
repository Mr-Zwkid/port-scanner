import sys
sys.path.append('src')
import tkinter as tk
from ui import PortScannerUI

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerUI(root)
    root.mainloop()
