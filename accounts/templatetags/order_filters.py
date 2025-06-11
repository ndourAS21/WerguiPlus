from django import template

register = template.Library()

@register.filter
def sum_items(items):
    return sum(item.quantity * item.unit_price for item in items)


@register.filter
def mul(value, arg):
    """Multiplies the value by the arg"""
    return value * arg


from django import template

register = template.Library()

@register.filter(name='mul')
def multiply(value, arg):
    """Multiplies the value by the arg"""
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return 0
    


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