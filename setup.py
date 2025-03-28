from setuptools import setup

setup(
    name='samr-enum',
    version='1.0.1',
    py_modules=['samr-enum'],
    install_requires=[
        'impacket>=0.12',
    ],
    entry_points={
        'console_scripts': [
            'samr-enum = samr-enum:main',
        ],
    },
    author='Enum D',
    author_email='study1@tuta.io',
    description='Python-based SAMR enumeration tool',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/studylab1/samr-enum',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
