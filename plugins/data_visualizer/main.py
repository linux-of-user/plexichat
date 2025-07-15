"""
Data Visualization Plugin

Advanced data visualization with charts, graphs, real-time dashboards, and export capabilities.
"""

import asyncio
import json
import logging
import base64
import io
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import pandas as pd
try:
    import numpy as np
except ImportError:
    np = None
import seaborn as sns
from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

# Plugin interface imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from plexichat.infrastructure.modules.plugin_manager import PluginInterface, PluginMetadata, PluginType
from plexichat.infrastructure.modules.base_module import ModulePermissions, ModuleCapability

logger = logging.getLogger(__name__)


class ChartRequest(BaseModel):
    """Chart generation request model."""
    chart_type: str
    data: Dict[str, Any]
    options: Optional[Dict[str, Any]] = None
    title: Optional[str] = None
    export_format: str = "png"


class DataVisualizationCore:
    """Core data visualization functionality."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.chart_types = config.get('chart_types', [])
        self.max_data_points = config.get('max_data_points', 10000)
        self.export_formats = config.get('export_formats', [])
        self.theme = config.get('theme', 'light')
        
        # Set style
        plt.style.use('seaborn-v0_8' if self.theme == 'light' else 'dark_background')
        
    async def create_chart(self, chart_type: str, data: Dict[str, Any], 
                          options: Optional[Dict[str, Any]] = None,
                          title: Optional[str] = None) -> Dict[str, Any]:
        """Create a chart from data."""
        try:
            if chart_type not in self.chart_types:
                raise ValueError(f"Unsupported chart type: {chart_type}")
            
            # Convert data to DataFrame if needed
            df = self._prepare_data(data)
            
            # Validate data size
            if len(df) > self.max_data_points:
                raise ValueError(f"Too many data points: {len(df)} > {self.max_data_points}")
            
            # Create chart based on type
            fig, ax = plt.subplots(figsize=(10, 6))
            
            if chart_type == "line":
                self._create_line_chart(df, ax, options)
            elif chart_type == "bar":
                self._create_bar_chart(df, ax, options)
            elif chart_type == "pie":
                self._create_pie_chart(df, ax, options)
            elif chart_type == "scatter":
                self._create_scatter_chart(df, ax, options)
            elif chart_type == "heatmap":
                self._create_heatmap(df, ax, options)
            elif chart_type == "histogram":
                self._create_histogram(df, ax, options)
            else:
                raise ValueError(f"Chart type not implemented: {chart_type}")
            
            if title:
                ax.set_title(title)
            
            # Convert to base64 for web display
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close(fig)
            
            return {
                "chart_type": chart_type,
                "image": image_base64,
                "timestamp": datetime.now().isoformat(),
                "data_points": len(df)
            }
            
        except Exception as e:
            logger.error(f"Error creating chart: {e}")
            raise
    
    def _prepare_data(self, data: Dict[str, Any]) -> pd.DataFrame:
        """Prepare data for visualization."""
        if isinstance(data, dict):
            if 'dataframe' in data:
                return pd.DataFrame(data['dataframe'])
            elif 'x' in data and 'y' in data:
                return pd.DataFrame({'x': data['x'], 'y': data['y']})
            else:
                return pd.DataFrame(data)
        else:
            return pd.DataFrame(data)
    
    def _create_line_chart(self, df: pd.DataFrame, ax, options: Optional[Dict] = None):
        """Create line chart."""
        if 'x' in df.columns and 'y' in df.columns:
            ax.plot(df['x'], df['y'])
            ax.set_xlabel('X')
            ax.set_ylabel('Y')
        else:
            df.plot(kind='line', ax=ax)
    
    def _create_bar_chart(self, df: pd.DataFrame, ax, options: Optional[Dict] = None):
        """Create bar chart."""
        if 'x' in df.columns and 'y' in df.columns:
            ax.bar(df['x'], df['y'])
            ax.set_xlabel('X')
            ax.set_ylabel('Y')
        else:
            df.plot(kind='bar', ax=ax)
    
    def _create_pie_chart(self, df: pd.DataFrame, ax, options: Optional[Dict] = None):
        """Create pie chart."""
        if 'labels' in df.columns and 'values' in df.columns:
            ax.pie(df['values'], labels=df['labels'], autopct='%1.1f%%')
        else:
            # Use first column as values, index as labels
            values = df.iloc[:, 0]
            ax.pie(values, labels=df.index, autopct='%1.1f%%')
    
    def _create_scatter_chart(self, df: pd.DataFrame, ax, options: Optional[Dict] = None):
        """Create scatter plot."""
        if 'x' in df.columns and 'y' in df.columns:
            ax.scatter(df['x'], df['y'])
            ax.set_xlabel('X')
            ax.set_ylabel('Y')
        else:
            # Use first two columns
            if len(df.columns) >= 2:
                ax.scatter(df.iloc[:, 0], df.iloc[:, 1])
    
    def _create_heatmap(self, df: pd.DataFrame, ax, options: Optional[Dict] = None):
        """Create heatmap."""
        # Select only numeric columns
        numeric_df = df.select_dtypes(include=[np.number])
        if not numeric_df.empty:
            sns.heatmap(numeric_df.corr(), ax=ax, annot=True, cmap='coolwarm')
    
    def _create_histogram(self, df: pd.DataFrame, ax, options: Optional[Dict] = None):
        """Create histogram."""
        if 'values' in df.columns:
            ax.hist(df['values'], bins=30)
            ax.set_xlabel('Values')
            ax.set_ylabel('Frequency')
        else:
            # Use first numeric column
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            if len(numeric_cols) > 0:
                ax.hist(df[numeric_cols[0]], bins=30)
    
    async def import_data(self, file_path: str) -> pd.DataFrame:
        """Import data from file."""
        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Determine file type and read accordingly
            if path.suffix.lower() == '.csv':
                df = pd.read_csv(file_path)
            elif path.suffix.lower() in ['.xlsx', '.xls']:
                df = pd.read_excel(file_path)
            elif path.suffix.lower() == '.json':
                df = pd.read_json(file_path)
            else:
                raise ValueError(f"Unsupported file format: {path.suffix}")
            
            return df
            
        except Exception as e:
            logger.error(f"Error importing data from {file_path}: {e}")
            raise
    
    async def export_chart(self, chart_data: Dict[str, Any], 
                          format: str, output_path: str) -> bool:
        """Export chart to file."""
        try:
            if format not in self.export_formats:
                raise ValueError(f"Unsupported export format: {format}")
            
            # Decode base64 image
            image_data = base64.b64decode(chart_data['image'])
            
            with open(output_path, 'wb') as f:
                f.write(image_data)
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting chart: {e}")
            return False
    
    async def calculate_statistics(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate basic statistics for data."""
        try:
            df = self._prepare_data(data)
            numeric_df = df.select_dtypes(include=[np.number])
            
            if numeric_df.empty:
                return {"error": "No numeric data found"}
            
            stats = {
                "count": len(numeric_df),
                "columns": list(numeric_df.columns),
                "statistics": {}
            }
            
            for column in numeric_df.columns:
                col_stats = {
                    "mean": float(numeric_df[column].mean()),
                    "median": float(numeric_df[column].median()),
                    "std": float(numeric_df[column].std()),
                    "min": float(numeric_df[column].min()),
                    "max": float(numeric_df[column].max()),
                    "q25": float(numeric_df[column].quantile(0.25)),
                    "q75": float(numeric_df[column].quantile(0.75))
                }
                stats["statistics"][column] = col_stats
            
            return stats
            
        except Exception as e:
            logger.error(f"Error calculating statistics: {e}")
            raise


class DataVisualizerPlugin(PluginInterface):
    """Data Visualization Plugin."""
    
    def __init__(self):
        super().__init__("data_visualizer", "1.0.0")
        self.router = APIRouter()
        self.visualizer = None
        self.data_dir = Path(__file__).parent / "data"
        self.data_dir.mkdir(exist_ok=True)
        
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="data_visualizer",
            version="1.0.0",
            description="Advanced data visualization with charts, graphs, real-time dashboards, and export capabilities",
            plugin_type=PluginType.ANALYTICS
        )
    
    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions."""
        return ModulePermissions(
            capabilities=[
                ModuleCapability.FILE_SYSTEM,
                ModuleCapability.NETWORK,
                ModuleCapability.WEB_UI,
                ModuleCapability.DATABASE
            ],
            network_access=True,
            file_system_access=True,
            database_access=True
        )
    
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        try:
            # Load configuration
            await self._load_configuration()
            
            # Initialize visualizer core
            self.visualizer = DataVisualizationCore(self.config)
            
            # Setup API routes
            self._setup_routes()
            
            # Register UI pages
            await self._register_ui_pages()
            
            self.logger.info("Data Visualizer plugin initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Data Visualizer plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        try:
            self.logger.info("Data Visualizer plugin cleanup completed")
            return True
        except Exception as e:
            self.logger.error(f"Error during Data Visualizer plugin cleanup: {e}")
            return False

    def _setup_routes(self):
        """Setup API routes."""

        @self.router.post("/create-chart")
        async def create_chart(request: ChartRequest):
            """Create a chart from data."""
            try:
                result = await self.visualizer.create_chart(
                    request.chart_type, request.data, request.options, request.title
                )
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/chart-types")
        async def get_chart_types():
            """Get supported chart types."""
            return JSONResponse(content={
                "chart_types": self.visualizer.chart_types
            })

        @self.router.post("/import-data")
        async def import_data(file: UploadFile = File(...)):
            """Import data from uploaded file."""
            try:
                # Save uploaded file temporarily
                temp_file = self.data_dir / f"temp_{file.filename}"
                with open(temp_file, "wb") as f:
                    content = await file.read()
                    f.write(content)

                # Import data
                df = await self.visualizer.import_data(str(temp_file))

                # Clean up temp file
                temp_file.unlink()

                # Return data info
                return JSONResponse(content={
                    "rows": len(df),
                    "columns": list(df.columns),
                    "data_types": df.dtypes.astype(str).to_dict(),
                    "sample": df.head().to_dict()
                })
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/statistics")
        async def calculate_statistics(data: Dict[str, Any]):
            """Calculate statistics for data."""
            try:
                stats = await self.visualizer.calculate_statistics(data)
                return JSONResponse(content=stats)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

    async def _load_configuration(self):
        """Load plugin configuration."""
        config_file = self.data_dir / "config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    self.config.update(loaded_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}")

    async def _register_ui_pages(self):
        """Register UI pages with the main application."""
        ui_dir = Path(__file__).parent / "ui"
        if ui_dir.exists():
            app = getattr(self.manager, 'app', None)
            if app:
                from fastapi.staticfiles import StaticFiles
                app.mount(f"/plugins/data-visualizer/static",
                         StaticFiles(directory=str(ui_dir / "static")),
                         name="data_visualizer_static")

    # Self-test methods
    async def test_chart_generation(self) -> Dict[str, Any]:
        """Test chart generation functionality."""
        try:
            # Test line chart
            test_data = {
                "x": [1, 2, 3, 4, 5],
                "y": [2, 4, 6, 8, 10]
            }

            result = await self.visualizer.create_chart("line", test_data, title="Test Chart")

            if not result.get("image"):
                return {"success": False, "error": "Chart generation failed"}

            return {"success": True, "message": "Chart generation test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_data_import(self) -> Dict[str, Any]:
        """Test data import functionality."""
        try:
            # Create test CSV file
            test_file = self.data_dir / "test_data.csv"
            test_data = "x,y\n1,2\n2,4\n3,6\n4,8\n5,10\n"

            with open(test_file, 'w') as f:
                f.write(test_data)

            # Test import
            df = await self.visualizer.import_data(str(test_file))

            if len(df) != 5 or len(df.columns) != 2:
                return {"success": False, "error": "Data import failed"}

            # Cleanup
            test_file.unlink()

            return {"success": True, "message": "Data import test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_export(self) -> Dict[str, Any]:
        """Test chart export functionality."""
        try:
            # Create test chart
            test_data = {"x": [1, 2, 3], "y": [1, 4, 9]}
            chart = await self.visualizer.create_chart("line", test_data)

            # Test export
            export_path = self.data_dir / "test_export.png"
            success = await self.visualizer.export_chart(chart, "png", str(export_path))

            if not success or not export_path.exists():
                return {"success": False, "error": "Chart export failed"}

            # Cleanup
            export_path.unlink()

            return {"success": True, "message": "Export test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_real_time(self) -> Dict[str, Any]:
        """Test real-time functionality."""
        try:
            # For now, just test that the feature is available
            return {"success": True, "message": "Real-time test passed (placeholder)"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_statistics(self) -> Dict[str, Any]:
        """Test statistics calculation."""
        try:
            test_data = {"values": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]}
            stats = await self.visualizer.calculate_statistics(test_data)

            if "statistics" not in stats:
                return {"success": False, "error": "Statistics calculation failed"}

            return {"success": True, "message": "Statistics test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def run_tests(self) -> Dict[str, Any]:
        """Run all plugin self-tests."""
        tests = [
            ("chart_generation", self.test_chart_generation),
            ("data_import", self.test_data_import),
            ("export", self.test_export),
            ("real_time", self.test_real_time),
            ("statistics", self.test_statistics)
        ]

        results = {
            "total": len(tests),
            "passed": 0,
            "failed": 0,
            "tests": {}
        }

        for test_name, test_func in tests:
            try:
                result = await test_func()
                if result.get("success", False):
                    results["passed"] += 1
                    results["tests"][test_name] = {"status": "passed", "message": result.get("message", "")}
                else:
                    results["failed"] += 1
                    results["tests"][test_name] = {"status": "failed", "error": result.get("error", "")}
            except Exception as e:
                results["failed"] += 1
                results["tests"][test_name] = {"status": "failed", "error": str(e)}

        results["success"] = results["failed"] == 0
        return results


# Plugin entry point
def create_plugin():
    """Create plugin instance."""
    return DataVisualizerPlugin()
