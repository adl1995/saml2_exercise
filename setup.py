from setuptools import setup, find_packages

setup(
    name='saml2_exercise',
    version="0.1",
    author='GEANT',
    author_email='swd@geant.org',
    description='SAML2 Devops Assessment',
    url='https://github.com/erik-geant/saml2_exercise',
    packages=find_packages(),
    install_requires=[
        'flask',
        'Flask-SAML',
        'Flask-Principal',
    ]
)
