from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    install_requires = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="cryptapipe",
    version="0.1.0",
    description="End-to-end encrypted secure data pipeline",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cryptapipe/cryptapipe",
    license="MIT",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11",
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "cryptapipe=main:entry",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
    ],
)
