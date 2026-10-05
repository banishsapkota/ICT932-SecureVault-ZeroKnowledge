{% extends 'base.html' %}
{% block title %}Admin Dashboard | SecureVault{% endblock %}
{% block content %}
<div class="card p-4">
    <h2>Administrative Dashboard</h2>
    <div class="row g-3 mt-2">
        <div class="col-md-6">
            <h4>Users</h4>
            <table class="table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td>{{ user.role }}</td>
                        <td>{% if user.locked_until %}Locked{% else %}Active{% endif %}</td>
                        <td>
                            <form method="post" action="{{ url_for('admin.lock_user', user_id=user.id) }}">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />
                                <button type="submit" class="btn btn-sm btn-warning">Lock</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        <div class="col-md-6">
            <h4>Audit Log</h4>
            <table class="table">
                <thead>
                    <tr>
                        <th>Event</th>
                        <th>Details</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs %}
                    <tr>
                        <td>{{ log.event_type }}</td>
                        <td>{{ log.details }}</td>
                        <td>{{ log.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endblock %}
