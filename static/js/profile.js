// Profile Management Functions (Bootstrap 5 safe)
document.addEventListener('DOMContentLoaded', function () {
    // If the modal exists, move it to be a direct child of <body>
    // This prevents "unclickable modal" issues caused by parent stacking contexts (transform/z-index/etc.)
    const modalElement = document.getElementById('editProfileModal');
    if (modalElement && modalElement.parentElement !== document.body) {
        document.body.appendChild(modalElement);
    }

    // Optional: clean up stuck backdrops (can happen if a modal is closed incorrectly)
    document.querySelectorAll('.modal-backdrop').forEach((b, idx, arr) => {
        // leave only the last one
        if (idx !== arr.length - 1) b.remove();
    });

    // Debug
    console.log('Profile page loaded. Modal found:', !!modalElement);
});

// Use ONE saveProfile function globally (don’t redefine it inside templates)
function saveProfile() {
    const form = document.getElementById('profileForm');
    if (!form) {
        alert('Profile form not found.');
        return;
    }

    // Collect values by id (your templates use ids, not name= fields)
    const data = {
        name: document.getElementById('name')?.value || '',
        email: document.getElementById('email')?.value || '',
        role: document.getElementById('role')?.value,
        student_id: document.getElementById('student_id')?.value,
        major: document.getElementById('major')?.value,
        enrollment_year: document.getElementById('enrollment_year')?.value,
        department: document.getElementById('department')?.value,
        employee_id: document.getElementById('employee_id')?.value,
        office_location: document.getElementById('office_location')?.value,
        office_hours: document.getElementById('office_hours')?.value,
    };

    // remove undefined keys
    Object.keys(data).forEach(k => data[k] === undefined && delete data[k]);

    const current_password = document.getElementById('current_password')?.value || '';
    const new_password = document.getElementById('new_password')?.value || '';
    const confirm_password = document.getElementById('confirm_password')?.value || '';

    if (new_password.trim() !== '') {
        if (!current_password.trim()) {
            alert('Please enter your current password');
            return;
        }
        if (new_password !== confirm_password) {
            alert('New passwords do not match');
            return;
        }
        if (new_password.length < 6) {
            alert('Password must be at least 6 characters');
            return;
        }
        data.current_password = current_password;
        data.new_password = new_password;
    }

    const saveButton = document.querySelector('#editProfileModal .btn-primary');
    const originalText = saveButton ? saveButton.innerHTML : null;
    if (saveButton) {
        saveButton.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Saving...';
        saveButton.disabled = true;
    }

    fetch('/profile/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
        .then(async (response) => {
            // If backend returns HTML error page, this prevents "Unexpected token <"
            const text = await response.text();
            try {
                return JSON.parse(text);
            } catch {
                throw new Error(text.slice(0, 200));
            }
        })
        .then((responseData) => {
            if (saveButton) {
                saveButton.innerHTML = originalText;
                saveButton.disabled = false;
            }

            if (responseData.success) {
                alert(responseData.message || 'Profile updated successfully');

                const modalEl = document.getElementById('editProfileModal');
                const modal = bootstrap.Modal.getInstance(modalEl);
                if (modal) modal.hide();

                setTimeout(() => location.reload(), 400);
            } else {
                alert('Error: ' + (responseData.message || 'Unknown error'));
            }
        })
        .catch((error) => {
            console.error('Profile update error:', error);

            if (saveButton) {
                saveButton.innerHTML = originalText;
                saveButton.disabled = false;
            }

            alert('An error occurred while updating profile.\n\n' + error.message);
        });
}
