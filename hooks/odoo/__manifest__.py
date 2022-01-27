# -*- coding: utf-8 -*-
# Manifest for the Odoo module
{
    'name': "Blackfire",

    'summary': 'Profile Odoo with Blackfire.io',

    'description': """
Profile with Blackfire.io
=========================
Allows users and developers profiling/monitoring of Odoo applications with Blackfire.io.
    """,

    'author': "Blackfire.io",
    'website': "https://www.blackfire.io",

    'category': 'Technical',
    'version': '0.1',
    'license': 'MIT',

    # any module necessary for this one to work correctly
    'depends': ['base'],

    'external_dependencies': {
        'python': ['blackfire']
    },

    'auto_install': True,

    # Hook function called after Odoo has been loaded
    # See https://odoo-development.readthedocs.io/en/latest/dev/hooks/post_load.html
    'post_load': '_blackfire_post_load'
}
