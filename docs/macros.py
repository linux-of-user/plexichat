"""
Simple MkDocs macros module used by the macros plugin. Kept minimal to avoid import errors.
"""

def define_env(env):
    """Define simple macros for templates."""
    env.variables['project_name'] = 'PlexiChat'
    env.variables['version'] = '0.0.0'
