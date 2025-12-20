
import streamlit as st
import pandas as pd
from password_tool.checker import PasswordChecker
from password_tool.generator import PasswordGenerator, PasswordStrength


def initialize_session_state():
    # Initialize Streamlit session state variables
    if 'checker' not in st.session_state:
        st.session_state.checker = PasswordChecker()
    if 'generator' not in st.session_state:
        st.session_state.generator = PasswordGenerator()
    if 'generated_passwords' not in st.session_state:
        st.session_state.generated_passwords = []
    if 'check_history' not in st.session_state:
        st.session_state.check_history = []


def format_strength_badge(strength: str) -> str:
    # Format strength level with emoji and color
    badges = {
        "VERY WEAK": "🔴 VERY WEAK",
        "WEAK": "🟠 WEAK",
        "MEDIUM": "🟡 MEDIUM",
        "STRONG": "🟢 STRONG",
    }
    return badges.get(strength, strength)


def render_password_checker():
    # Render password checker section
    st.header("🔍 Password Checker")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        password_input = st.text_input(
            "Enter password to check:",
            type="password",
            placeholder="Type your password here..."
        )
    
    with col2:
        check_button = st.button("🔎 Check", use_container_width=True)
    
    if check_button and password_input:
        # Check password
        result = st.session_state.checker.check_password(password_input)
        
        # Store in history
        st.session_state.check_history.append({
            'password': '***',
            'strength': result['overall_strength'],
            'score': result['score'],
            'entropy': result['entropy_bits']
        })
        
        # Display results
        st.divider()
        
        # Strength indicator
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Strength", format_strength_badge(result['overall_strength']))
        
        with col2:
            st.metric("Score", f"{result['score']}/100")
        
        with col3:
            st.metric("Entropy", f"{result['entropy_bits']} bits")
        
        with col4:
            st.metric("Time to Crack", result['time_to_crack'])
        
        # Detailed feedback
        st.subheader("📋 Detailed Analysis")
        
        # Criteria checklist
        criteria_col1, criteria_col2 = st.columns(2)
        
        with criteria_col1:
            st.write("**Security Criteria:**")
            for criterion, status_dict in list(result['criteria'].items())[:4]:
                status = "✅" if status_dict['status'] == "PASS" else "❌"
                clean_name = criterion.replace('_', ' ').title()
                st.write(f"{status} {clean_name}")
        
        with criteria_col2:
            st.write("**Additional Checks:**")
            for criterion, status_dict in list(result['criteria'].items())[4:]:
                status = "✅" if status_dict['status'] == "PASS" else "❌"
                clean_name = criterion.replace('_', ' ').title()
                st.write(f"{status} {clean_name}")
        
        # Feedback sections
        st.divider()
        
        if result['feedback']['positive']:
            with st.expander("✨ Positive Feedback", expanded=True):
                for point in result['feedback']['positive']:
                    st.success(f"✓ {point}")
        
        if result['feedback']['negative']:
            with st.expander("⚠️ Areas to Improve", expanded=True):
                for point in result['feedback']['negative']:
                    st.warning(f"✗ {point}")
        
        if result['feedback']['suggestions']:
            with st.expander("💡 Suggestions", expanded=True):
                for suggestion in result['feedback']['suggestions']:
                    st.info(f"→ {suggestion}")
        
        # Recommendation
        st.divider()
        if result['overall_strength'] == "STRONG":
            st.success("✅ This is a strong password! Use it with confidence.")
        elif result['overall_strength'] == "MEDIUM":
            st.warning("⚠️ This password is acceptable but could be improved.")
        else:
            st.error("❌ This password is weak. Please use a stronger password.")
    
    elif check_button:
        st.warning("Please enter a password to check.")


def render_password_generator():
    # Render password generator section
    st.header("⚡ Password Generator")
    
    # Configuration columns
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        strength = st.selectbox(
            "Strength Level",
            options=["WEAK", "MEDIUM", "STRONG", "VERY_STRONG"],
            help="Higher strength = longer password with more character types"
        )
    
    with col2:
        length = st.slider(
            "Password Length",
            min_value=8,
            max_value=32,
            value=16,
            help="NIST recommends minimum 12 characters"
        )
    
    with col3:
        include_special = st.checkbox("Special Chars", value=True)
    
    with col4:
        readable = st.checkbox("Readable", value=False, help="Easier to remember")
    
    # Generate buttons
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔐 Generate", use_container_width=True):
            try:
                pwd = st.session_state.generator.generate_password(
                    length=length,
                    strength=PasswordStrength[strength],
                    include_special=include_special,
                    readable=readable
                )
                st.session_state.generated_passwords.append({
                    'password': pwd,
                    'strength': strength,
                    'length': length,
                    'timestamp': pd.Timestamp.now()
                })
                st.success("Password generated!")
            except Exception as e:
                st.error(f"Error generating password: {e}")
    
    with col2:
        if st.button("🔄 Generate Multiple", use_container_width=True):
            try:
                count = st.number_input("How many?", min_value=1, max_value=10, value=5)
                pwds = st.session_state.generator.generate_multiple(
                    count=count,
                    length=length,
                    strength=PasswordStrength[strength]
                )
                for pwd in pwds:
                    st.session_state.generated_passwords.append({
                        'password': pwd,
                        'strength': strength,
                        'length': length,
                        'timestamp': pd.Timestamp.now()
                    })
                st.success(f"Generated {count} passwords!")
            except Exception as e:
                st.error(f"Error: {e}")
    
    with col3:
        if st.button("🗑️ Clear History", use_container_width=True):
            st.session_state.generated_passwords = []
            st.info("History cleared!")
    
    # Display strength info
    st.divider()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Strength Levels:**")
        for strength_level in PasswordStrength:
            title, desc = PasswordGenerator.get_strength_description(strength_level)
            rec_length = PasswordGenerator.get_recommended_length(strength_level)
            st.write(f"**{strength_level.value}**: {desc} ({rec_length}+ chars)")
    
    with col2:
        st.write("**Entropy Information:**")
        charset_size = PasswordGenerator.get_charset_size(
            include_special=include_special
        )
        entropy = PasswordGenerator.calculate_entropy(length, charset_size)
        st.metric("Password Entropy", f"{entropy:.1f} bits")
        
        if entropy < 50:
            st.warning("⚠️ Low entropy - consider longer password")
        elif entropy < 70:
            st.info("ℹ️ Acceptable entropy")
        else:
            st.success("✅ Excellent entropy")
    
    # Display generated passwords
    if st.session_state.generated_passwords:
        st.divider()
        st.subheader("📋 Generated Passwords")
        
        # Create DataFrame for display
        df = pd.DataFrame(st.session_state.generated_passwords)
        
        # Display as table
        st.dataframe(
            df[['password', 'strength', 'length']],
            use_container_width=True,
            hide_index=True
        )
        
        # Copy to clipboard option
        if len(st.session_state.generated_passwords) > 0:
            latest_pwd = st.session_state.generated_passwords[-1]['password']
            st.code(latest_pwd, language="text")
            st.caption("Use the button at the top-right corner of the code block to copy")


def render_batch_audit():
    # Render batch password audit section
    st.header("📊 Batch Password Audit")
    
    st.write("Paste multiple passwords (one per line) to audit them all at once.")
    
    passwords_input = st.text_area(
        "Enter passwords (one per line):",
        placeholder="password1\npassword2\npassword3",
        height=150
    )
    
    if st.button("🚀 Audit All Passwords"):
        if passwords_input.strip():
            passwords = [p.strip() for p in passwords_input.split('\n') if p.strip()]
            
            results = []
            progress_bar = st.progress(0)
            
            for i, pwd in enumerate(passwords):
                result = st.session_state.checker.check_password(pwd)
                results.append({
                    'Password': '***',
                    'Strength': result['overall_strength'],
                    'Score': result['score'],
                    'Entropy': result['entropy_bits'],
                    'Time to Crack': result['time_to_crack']
                })
                progress_bar.progress((i + 1) / len(passwords))
            
            # Display results
            st.divider()
            st.subheader("📈 Audit Results")
            
            df = pd.DataFrame(results)
            st.dataframe(df, use_container_width=True, hide_index=True)
            
            # Summary statistics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                strong_count = len([r for r in results if r['Strength'] == 'STRONG'])
                st.metric("Strong", strong_count)
            
            with col2:
                medium_count = len([r for r in results if r['Strength'] == 'MEDIUM'])
                st.metric("Medium", medium_count)
            
            with col3:
                weak_count = len([r for r in results if r['Strength'] in ['WEAK', 'VERY WEAK']])
                st.metric("Weak", weak_count)
            
            with col4:
                avg_score = df['Score'].mean()
                st.metric("Avg Score", f"{avg_score:.0f}/100")
            
            # Download results as CSV
            csv = df.to_csv(index=False)
            st.download_button(
                label="📥 Download Results (CSV)",
                data=csv,
                file_name="password_audit_results.csv",
                mime="text/csv"
            )
        else:
            st.warning("Please enter at least one password.")


def render_info_page():
    # Render information and documentation page
    st.header("ℹ️ About This Tool")
    
    st.markdown("""
    ### Password Audit Tool
    
    An intensive password strength checker and generator built with Streamlit.
    
    **Features:**
    - 🔍 Advanced password strength analysis with entropy calculation
    - ⚡ Cryptographically secure password generation
    - 📊 Batch password auditing
    - 🎯 Detailed security feedback and recommendations
    
    ### How It Works
    
    #### Password Checker
    - **Entropy Analysis**: Calculates Shannon entropy to determine actual password strength
    - **Pattern Detection**: Identifies keyboard patterns, sequential chars, and common substitutions
    - **Dictionary Check**: Compares against known common passwords and breached databases
    - **Time to Crack**: Estimates how long it would take to crack the password
    
    #### Password Generator
    - **Cryptographic Security**: Uses `secrets` module for true randomness
    - **Strength Levels**: From WEAK (quick remembering) to VERY_STRONG (maximum security)
    - **Character Diversity**: Guarantees mix of uppercase, lowercase, numbers, and special chars
    - **Batch Generation**: Generate multiple passwords at once
    
    ### NIST Recommendations
    - ✅ Minimum 12 characters
    - ✅ Mix of character types (uppercase, lowercase, numbers, special chars)
    - ✅ Avoid dictionary words and common patterns
    - ✅ Entropy should be 50+ bits (acceptable), 70+ bits (strong)
    
    ### Security Criteria
    The tool evaluates passwords across multiple dimensions:
    - **Length**: Minimum 12 characters recommended
    - **Character Diversity**: Uppercase, lowercase, numbers, special characters
    - **Pattern Detection**: Avoids keyboard walks and sequential characters
    - **Dictionary Checking**: Not in common password lists
    - **Entropy**: Sufficient randomness and unpredictability
    
    ### For Best Results
    1. Use 16+ character passwords for important accounts
    2. Mix all character types (uppercase, lowercase, numbers, special)
    3. Avoid personal information, names, or dictionary words
    4. Use unique passwords for each account
    5. Consider using a password manager for storage
    """)
    
    st.divider()
    
    st.markdown("""
    ### Understanding Strength Levels
    
    **WEAK (8+ chars, letters + numbers)**
    - Basic protection
    - ~40 bits entropy
    - Good for: Throwaway accounts
    
    **MEDIUM (12+ chars, mixed types)**
    - Standard protection
    - ~60 bits entropy
    - Good for: Regular accounts
    
    **STRONG (16+ chars, all types + special)**
    - Good protection
    - ~70 bits entropy
    - Good for: Email, banking
    
    **VERY_STRONG (20+ chars, maximum diversity)**
    - Maximum protection
    - ~80+ bits entropy
    - Good for: Critical accounts (email, financial, security)
    """)


def main():
    # Main Streamlit application
    # Page configuration
    st.set_page_config(
        page_title="Password Audit Tool",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS for better styling
    st.markdown("""
        <style>
        .metric-card {
            background-color: #f0f2f6;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Initialize session state
    initialize_session_state()
    
    # Sidebar navigation
    st.sidebar.title("🔐 Password Audit Tool")
    page = st.sidebar.radio(
        "Navigation",
        ["Check Password", "Generate Password", "Batch Audit", "Information"]
    )
    
    st.sidebar.divider()
    
    # Sidebar 
    if st.session_state.check_history:
        st.sidebar.subheader("📊 Check History")
        latest_checks = st.session_state.check_history[-5:]
        for check in reversed(latest_checks):
            st.sidebar.write(f"Score: {check['score']}/100 - {check['strength']}")
    
    # Main content
    if page == "Check Password":
        render_password_checker()
    elif page == "Generate Password":
        render_password_generator()
    elif page == "Batch Audit":
        render_batch_audit()
    else:
        render_info_page()
    
    # Footer
    st.divider()
    st.caption("🔐 Password Audit Tool | Built with Streamlit")


if __name__ == "__main__":
    main()
