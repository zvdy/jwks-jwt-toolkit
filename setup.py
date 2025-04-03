from setuptools import setup, find_packages

setup(
    name="jwks",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "flask>=2.0.0",
        "PyJWT>=2.3.0",
        "cryptography>=36.0.0",
        "requests>=2.27.0",
    ],
    author="JWKS Team",
    author_email="info@example.com",
    description="A professional JWKS server and JWT client implementation",
    keywords="jwt, jwks, security, authentication",
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "jwks-server=jwks_server.app:main",
            "jwt-client=jwt_client.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security :: Cryptography",
    ],
)
