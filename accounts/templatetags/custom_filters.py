from django import template

register = template.Library()

@register.filter
def sum_items(items):
    """Calcule la somme des items (quantity * unit_price)"""
    return sum(item.quantity * item.unit_price for item in items)

@register.filter
def mul(value, arg):
    """Multiplie deux valeurs"""
    return value * arg