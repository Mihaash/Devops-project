import dash
from dash import dcc, html, Input, Output, callback, dash_table
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta
import dash_bootstrap_components as dbc
from typing import Dict, List, Any
import logging

class SecurityDashboard:
    """Real-time security dashboard with dark theme"""
    
    def __init__(self, alert_system, config: Dict[str, Any]):
        self.alert_system = alert_system
        self.config = config
        self.dashboard_config = config.get("dashboard", {})
        self.logger = logging.getLogger(__name__)
        
        # Initialize Dash app with dark theme
        self.app = dash.Dash(__name__, 
                           external_stylesheets=[dbc.themes.DARKLY, 
                                               dbc.icons.BOOTSTRAP],
                           meta_tags=[{"name": "viewport", 
                                     "content": "width=device-width, initial-scale=1"}])
        
        self.setup_layout()
        self.setup_callbacks()
    
    def setup_layout(self):
        """Setup the dashboard layout"""
        self.app.layout = dbc.Container([
            # Header
            dbc.Row([
                dbc.Col([
                    html.H1("🛡️ Security Operations Center Dashboard", 
                           className="text-center mb-4 text-danger"),
                    html.H4("Real-time Threat Intelligence & Alert Monitoring", 
                           className="text-center text-muted mb-4")
                ])
            ]),
            
            # Auto-refresh component
            dcc.Interval(
                id='interval-component',
                interval=self.dashboard_config.get("auto_refresh_interval", 30) * 1000,
                n_intervals=0
            ),
            
            # Key Metrics Cards
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Total Alerts", className="card-title text-warning"),
                            html.H2(id="total-alerts", className="text-light")
                        ])
                    ], color="dark", outline=True)
                ], width=3),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Critical", className="card-title text-danger"),
                            html.H2(id="critical-alerts", className="text-light")
                        ])
                    ], color="dark", outline=True)
                ], width=3),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("High", className="card-title text-warning"),
                            html.H2(id="high-alerts", className="text-light")
                        ])
                    ], color="dark", outline=True)
                ], width=3),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Active Threats", className="card-title text-info"),
                            html.H2(id="active-alerts", className="text-light")
                        ])
                    ], color="dark", outline=True)
                ], width=3),
            ], className="mb-4"),
            
            # Charts Row
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Alert Severity Distribution", className="text-light"),
                        dbc.CardBody([
                            dcc.Graph(id="severity-pie-chart")
                        ])
                    ], color="dark", outline=True)
                ], width=6),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Alert Types", className="text-light"),
                        dbc.CardBody([
                            dcc.Graph(id="type-bar-chart")
                        ])
                    ], color="dark", outline=True)
                ], width=6),
            ], className="mb-4"),
            
            # Timeline Chart
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Alert Timeline (Last 24 Hours)", className="text-light"),
                        dbc.CardBody([
                            dcc.Graph(id="timeline-chart")
                        ])
                    ], color="dark", outline=True)
                ])
            ], className="mb-4"),
            
            # Alerts Table
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.H5("Recent Security Alerts", className="text-light mb-0"),
                            html.Small("Auto-refreshes every 30 seconds", className="text-muted")
                        ], className="text-light"),
                        dbc.CardBody([
                            dash_table.DataTable(
                                id='alerts-table',
                                columns=[
                                    {'name': 'Time', 'id': 'first_seen'},
                                    {'name': 'Severity', 'id': 'severity'},
                                    {'name': 'Type', 'id': 'type'},
                                    {'name': 'Title', 'id': 'title'},
                                    {'name': 'Asset', 'id': 'target_asset'},
                                    {'name': 'Source IP', 'id': 'source_ip'},
                                    {'name': 'Status', 'id': 'status'}
                                ],
                                style_cell={
                                    'backgroundColor': '#2b2b2b',
                                    'color': 'white',
                                    'border': '1px solid #444'
                                },
                                style_header={
                                    'backgroundColor': '#1a1a1a',
                                    'fontWeight': 'bold',
                                    'color': 'white'
                                },
                                style_data_conditional=[
                                    {
                                        'if': {'filter_query': '{severity} = Critical'},
                                        'backgroundColor': '#dc3545',
                                        'color': 'white',
                                    },
                                    {
                                        'if': {'filter_query': '{severity} = High'},
                                        'backgroundColor': '#fd7e14',
                                        'color': 'white',
                                    },
                                    {
                                        'if': {'filter_query': '{severity} = Medium'},
                                        'backgroundColor': '#ffc107',
                                        'color': 'black',
                                    }
                                ],
                                page_size=15,
                                sort_action="native",
                                filter_action="native"
                            )
                        ])
                    ], color="dark", outline=True)
                ])
            ]),
            
            # Footer
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.Hr(className="my-4"),
                        html.P(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                              className="text-center text-muted"),
                        html.P("Security Operations Center - Real-time Monitoring", 
                              className="text-center text-muted")
                    ])
                ])
            ])
            
        ], fluid=True, style={'backgroundColor': '#1a1a1a'})
    
    def setup_callbacks(self):
        """Setup dashboard callbacks for real-time updates"""
        
        @self.app.callback(
            [Output('total-alerts', 'children'),
             Output('critical-alerts', 'children'),
             Output('high-alerts', 'children'),
             Output('active-alerts', 'children'),
             Output('severity-pie-chart', 'figure'),
             Output('type-bar-chart', 'figure'),
             Output('timeline-chart', 'figure'),
             Output('alerts-table', 'data')],
            [Input('interval-component', 'n_intervals')]
        )
        def update_dashboard(n):
            try:
                # Get alert statistics
                stats = self.alert_system.get_alert_statistics()
                recent_alerts = self.alert_system.get_recent_alerts(100)
                
                # Update metric cards
                total_alerts = stats['total_alerts']
                critical_alerts = stats['by_severity'].get('Critical', 0)
                high_alerts = stats['by_severity'].get('High', 0)
                active_alerts = stats['active_alerts']
                
                # Create severity pie chart
                severity_data = stats['by_severity']
                severity_fig = self.create_pie_chart(severity_data, "Alert Severity Distribution")
                
                # Create type bar chart
                type_data = stats['by_type']
                type_fig = self.create_bar_chart(type_data, "Alert Types")
                
                # Create timeline chart
                timeline_fig = self.create_timeline_chart(recent_alerts)
                
                # Prepare table data
                table_data = []
                for alert in recent_alerts[:50]:  # Show last 50 alerts
                    table_data.append({
                        'first_seen': self.format_timestamp(alert['first_seen']),
                        'severity': alert['severity'],
                        'type': alert['type'],
                        'title': alert['title'][:50] + '...' if len(alert['title']) > 50 else alert['title'],
                        'target_asset': alert['target_asset'],
                        'source_ip': alert.get('source_ip', alert.get('target_ip', 'N/A')),
                        'status': alert['status']
                    })
                
                return (total_alerts, critical_alerts, high_alerts, active_alerts,
                       severity_fig, type_fig, timeline_fig, table_data)
                
            except Exception as e:
                self.logger.error(f"Error updating dashboard: {e}")
                # Return default values on error
                return (0, 0, 0, 0, 
                       self.create_pie_chart({}, "No Data"),
                       self.create_bar_chart({}, "No Data"),
                       self.create_timeline_chart([]), [])
    
    def create_pie_chart(self, data: Dict[str, int], title: str) -> go.Figure:
        """Create a pie chart for severity distribution"""
        if not data:
            # Create empty chart
            fig = go.Figure()
            fig.add_annotation(text="No Data Available", 
                            xref="paper", yref="paper",
                            x=0.5, y=0.5, showarrow=False,
                            font=dict(size=16, color="white"))
            fig.update_layout(
                title=title,
                paper_bgcolor='#2b2b2b',
                plot_bgcolor='#2b2b2b',
                font=dict(color="white")
            )
            return fig
        
        colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#28a745'
        }
        
        fig = go.Figure(data=[go.Pie(
            labels=list(data.keys()),
            values=list(data.values()),
            hole=0.3,
            marker_colors=[colors.get(sev, '#6c757d') for sev in data.keys()]
        )])
        
        fig.update_layout(
            title=title,
            paper_bgcolor='#2b2b2b',
            plot_bgcolor='#2b2b2b',
            font=dict(color="white"),
            showlegend=True
        )
        
        return fig
    
    def create_bar_chart(self, data: Dict[str, int], title: str) -> go.Figure:
        """Create a bar chart for alert types"""
        if not data:
            # Create empty chart
            fig = go.Figure()
            fig.add_annotation(text="No Data Available", 
                            xref="paper", yref="paper",
                            x=0.5, y=0.5, showarrow=False,
                            font=dict(size=16, color="white"))
            fig.update_layout(
                title=title,
                paper_bgcolor='#2b2b2b',
                plot_bgcolor='#2b2b2b',
                font=dict(color="white")
            )
            return fig
        
        fig = go.Figure(data=[go.Bar(
            x=list(data.keys()),
            y=list(data.values()),
            marker_color='#007bff'
        )])
        
        fig.update_layout(
            title=title,
            paper_bgcolor='#2b2b2b',
            plot_bgcolor='#2b2b2b',
            font=dict(color="white"),
            xaxis=dict(color="white"),
            yaxis=dict(color="white")
        )
        
        return fig
    
    def create_timeline_chart(self, alerts: List[Dict[str, Any]]) -> go.Figure:
        """Create a timeline chart showing alerts over time"""
        if not alerts:
            # Create empty chart
            fig = go.Figure()
            fig.add_annotation(text="No Data Available", 
                            xref="paper", yref="paper",
                            x=0.5, y=0.5, showarrow=False,
                            font=dict(size=16, color="white"))
            fig.update_layout(
                title="Alert Timeline (Last 24 Hours)",
                paper_bgcolor='#2b2b2b',
                plot_bgcolor='#2b2b2b',
                font=dict(color="white")
            )
            return fig
        
        # Group alerts by hour
        hourly_counts = {}
        now = datetime.now()
        
        for alert in alerts:
            try:
                alert_time = datetime.fromisoformat(alert['first_seen'].replace('Z', '+00:00'))
                if alert_time > now - timedelta(hours=24):
                    hour_key = alert_time.strftime('%H:00')
                    hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
            except:
                continue
        
        # Create timeline data
        hours = []
        counts = []
        
        for i in range(24):
            hour = (now - timedelta(hours=23-i)).strftime('%H:00')
            hours.append(hour)
            counts.append(hourly_counts.get(hour, 0))
        
        fig = go.Figure(data=[go.Scatter(
            x=hours,
            y=counts,
            mode='lines+markers',
            line=dict(color='#dc3545', width=3),
            marker=dict(color='#dc3545', size=6)
        )])
        
        fig.update_layout(
            title="Alert Timeline (Last 24 Hours)",
            paper_bgcolor='#2b2b2b',
            plot_bgcolor='#2b2b2b',
            font=dict(color="white"),
            xaxis=dict(
                title="Time",
                color="white",
                tickangle=45
            ),
            yaxis=dict(
                title="Number of Alerts",
                color="white"
            )
        )
        
        return fig
    
    def format_timestamp(self, timestamp: str) -> str:
        """Format timestamp for display"""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return timestamp
    
    def run(self, debug: bool = False):
        """Run the dashboard"""
        host = self.dashboard_config.get("host", "0.0.0.0")
        port = self.dashboard_config.get("port", 8050)
        
        self.logger.info(f"Starting dashboard on {host}:{port}")
        self.app.run_server(host=host, port=port, debug=debug)
