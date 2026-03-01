from jinja2 import Environment, PackageLoader, select_autoescape

# Initialize Jinja2 environment using PackageLoader
# This automatically finds the 'templates' folder within the 'auth_engine' package
jinja_env = Environment(
    loader=PackageLoader("auth_engine", "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)
