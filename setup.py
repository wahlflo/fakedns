import setuptools

with open('README.md', mode='r', encoding='utf-8') as readme_file:
    long_description = readme_file.read()


setuptools.setup(
    name="fakedns",
    version="1.1",
    author="Florian Wahl",
    author_email="florian.wahl.developer@gmail.com",
    description="A fake DNS server for malware analysis written in Python3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/wahlflo/fakedns",
    packages=setuptools.find_packages(),
    package_data={'fakedns': ['config/default_config.config']},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
       'cli-formatter>=1.2.0',
       'dns-messages>=1.0.0'
    ],
    entry_points={
        "console_scripts": [
            "fakedns=fakedns.fakedns_cli:main",
            "fakedns-config=fakedns.fakedns_config_cli:main"
        ],
    }
)