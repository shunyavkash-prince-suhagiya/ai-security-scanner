from setuptools import setup, find_packages

setup(
    name="ai-security-scanner",
    version="1.0.0",
    description="AI-powered system security scanner for credentials and sensitive data",
    author="Your Name",
    packages=find_packages(where="src"),
    py_modules=["main", "config", "web_app"],
    package_dir={"": "src"},
    install_requires=[
        "Flask>=3.1.0",
        "gunicorn>=23.0.0",
    ],
    entry_points={
        "console_scripts": [
            "sec-scan=main:main",
            "sec-scan-web=web_app:main",
        ],
    },
    python_requires=">=3.8",
)
