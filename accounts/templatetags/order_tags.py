from django import template

register = template.Library()

@register.filter
def sum_items(items):
    return sum(item.quantity * item.unit_price for item in items)