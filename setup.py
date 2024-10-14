from setuptools import setup, find_packages

setup(
    name='soso-server',
    version='0.1',
    packages=find_packages(),  # This will find all services automatically
    install_requires=[]  # Leave this empty if you use requirements.txt
)
