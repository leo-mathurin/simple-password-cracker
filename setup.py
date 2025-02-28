from setuptools import setup, find_packages

setup(
    name="password-cracker",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "tqdm>=4.64.0",
        "argparse>=1.4.0",
    ],
    entry_points={
        "console_scripts": [
            "password-cracker=cracker.cli:main",
        ],
    },
    python_requires=">=3.6",
    author="Léo Mathurin",
    author_email="leo.mathurin@epitech.eu",
    description="A simple password cracker using dictionary attacks",
    keywords="security, password, cracker, hash",
    url="https://github.com/leo-mathurin/simple-password-cracker",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
) 