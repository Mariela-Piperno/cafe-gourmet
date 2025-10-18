# Importações necessárias
from flask import Flask, render_template, request, redirect, url_for, session, flash
# --- IMPORTAÇÃO CORRIGIDA ---
from markupsafe import Markup
from functools import wraps
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired  # Mantemos isso para gerar tokens seguros

# Configura a conexão com o banco de dados
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'cafe_gourmet_db'
}

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'

# --- CONFIGURAÇÃO DE TOKEN (substitui a de e-mail) ---
s = URLSafeTimedSerializer(app.secret_key)

# Decorator para verificar se o usuário é admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or not session.get('is_admin'):
            flash('Você não tem permissão para acessar esta página.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- DICIONÁRIO DE PLANOS ---
PLANS = {
    'Clube do Grão': {'price': 79.90},
    'Seleção do Barista': {'price': 99.90},
    'Expresso Duplo': {'price': 149.90}
}

# --- ROTA PRINCIPAL '/' COM FILTROS ---
@app.route('/')
def index():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM categories ORDER BY name")
        categories = cursor.fetchall()
        category_id = request.args.get('category_id', type=int)
        sql = "SELECT * FROM products"
        params = []
        if category_id:
            sql += " WHERE category_id = %s"
            params.append(category_id)
        cursor.execute(sql, params)
        products = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('index.html', products=products, categories=categories, selected_category_id=category_id)
    except Exception as e:
        if 'Unknown column' in str(e) and 'category_id' in str(e):
             return ("ERRO: Parece que a sua tabela 'products' ainda não tem a coluna 'category_id' para fazer o filtro. "
                    "Execute o seguinte comando SQL para adicioná-la: "
                    "ALTER TABLE products ADD COLUMN category_id INT, ADD FOREIGN KEY (category_id) REFERENCES categories(id);")
        return f"Erro ao conectar ao banco: {e}"

# --- ROTAS GERAIS E DE CLIENTE ---
@app.route('/product/<int:product_id>')
def product(product_id):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
        product_data = cursor.fetchone()
        if not product_data:
            flash('Produto não encontrado!', 'danger')
            return redirect(url_for('index'))
        cursor.execute("SELECT r.rating, r.comment, r.created_at, u.name as user_name FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.product_id = %s ORDER BY r.created_at DESC", (product_id,))
        reviews = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('product_detail.html', product=product_data, reviews=reviews)
    except Exception as e:
        flash(f"Ocorreu um erro: {e}", 'danger')
        return redirect(url_for('index'))

@app.route('/subscriptions')
def subscriptions():
    plans_list = [
        {'name': 'Clube do Grão', 'price_str': '79,90', 'description': 'Receba todo mês um pacote de 250g do nosso café mais popular.', 'items': ['1x Café Clássico da Casa (250g)']},
        {'name': 'Seleção do Barista', 'price_str': '99,90', 'description': 'Receba um café especial de um micro-lote diferente a cada mês.', 'items': ['1x Café Especial do Mês (250g)']},
        {'name': 'Expresso Duplo', 'price_str': '149,90', 'description': 'Receba os dois cafés, o Clássico da Casa e o Especial do Mês.', 'items': ['1x Café Clássico (250g)', '1x Café Especial (250g)']}
    ]
    return render_template('subscriptions.html', plans=plans_list)

@app.route('/subscribe/<plan_name>')
def subscribe(plan_name):
    if 'loggedin' not in session:
        flash('Você precisa estar logado para assinar um plano.', 'warning')
        return redirect(url_for('login'))
    if plan_name not in PLANS:
        flash('Plano de assinatura inválido.', 'danger')
        return redirect(url_for('subscriptions'))
    cart = session.get('cart', {})
    if cart:
        flash('Seu carrinho foi limpo para prosseguir com a assinatura.', 'info')
        cart.clear()
    subscription_id = f"sub_{plan_name.replace(' ', '_')}"
    plan_details = PLANS[plan_name]
    cart[subscription_id] = { 'name': f"Assinatura: {plan_name}", 'price': plan_details['price'], 'quantity': 1, 'is_subscription': True }
    session['cart'] = cart
    session.modified = True
    return redirect(url_for('cart'))

# --- ROTAS DE AUTENTICAÇÃO E RECUPERAÇÃO DE SENHA ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        cpf = request.form['cpf']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, cpf, email, password_hash) VALUES (%s, %s, %s, %s)",
                           (name, cpf, email, hashed_password))
            conn.commit()
            cursor.close()
            conn.close()
            flash('Cadastro realizado com sucesso! Faça o login.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f'Erro ao cadastrar: {err}', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['loggedin'] = True
            session['id'] = user['id']
            session['name'] = user['name']
            session['is_admin'] = user.get('is_admin', False)
            return redirect(url_for('index'))
        else:
            flash('Email ou senha incorretos. Tente novamente.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/reset_password', methods=['GET', 'POST'])
def request_reset_token():
    if request.method == 'POST':
        email = request.form['email']
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            token = s.dumps(email, salt='password-reset-salt')
            link = url_for('reset_token', token=token, _external=True)
            
            flash_message = Markup(f'Simulação: O link de redefinição foi gerado. <a href="{link}" class="alert-link">Clique aqui para redefinir sua senha</a>.')
            flash(flash_message, 'info')
            
            return redirect(url_for('login'))
        else:
            flash('O e-mail informado não foi encontrado em nosso sistema.', 'warning')
            
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=1800)
    except SignatureExpired:
        flash('O link para redefinir a senha expirou. Por favor, solicite um novo.', 'warning')
        return redirect(url_for('request_reset_token'))
    except:
        flash('O link para redefinir a senha é inválido.', 'danger')
        return redirect(url_for('request_reset_token'))

    if request.method == 'POST':
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_password, email))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Sua senha foi atualizada com sucesso! Você já pode fazer o login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# --- ROTAS DE CARRINHO E PEDIDO ---
@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'loggedin' not in session:
        flash('Você precisa estar logado para adicionar itens ao carrinho!', 'warning')
        return redirect(url_for('login'))
    try:
        cart = session.get('cart', {})
        for item in cart.values():
            if item.get('is_subscription'):
                flash('Não é possível adicionar produtos ao finalizar uma assinatura. Finalize sua assinatura primeiro.', 'warning')
                return redirect(url_for('cart'))
        quantity = int(request.form.get('quantity', 1))
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT name, price, stock_quantity FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        cursor.close()
        conn.close()
        if not product:
            flash('Produto não encontrado!', 'danger')
            return redirect(url_for('index'))
        product_id_str = str(product_id)
        if product_id_str in cart:
            if cart[product_id_str]['quantity'] + quantity > product['stock_quantity']:
                flash(f'Estoque insuficiente para {product["name"]}.', 'warning')
            else:
                cart[product_id_str]['quantity'] += quantity
                flash(f'{product["name"]} adicionado ao carrinho!', 'success')
        else:
            if quantity > product['stock_quantity']:
                flash(f'Estoque insuficiente para {product["name"]}.', 'warning')
            else:
                cart[product_id_str] = {'name': product['name'], 'price': float(product['price']), 'quantity': quantity}
                flash(f'{product["name"]} adicionado ao carrinho!', 'success')
        session['cart'] = cart
        session.modified = True
    except Exception as e:
        flash(f'Ocorreu um erro: {e}', 'danger')
    return redirect(url_for('index'))
@app.route('/cart')
def cart():
    if 'loggedin' not in session:
        flash('Faça login para ver seu carrinho.', 'warning')
        return redirect(url_for('login'))
    cart_items = session.get('cart', {})
    total_price = sum(item['price'] * item['quantity'] for item in cart_items.values())
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)
@app.route('/remove_from_cart/<product_id>')
def remove_from_cart(product_id):
    if 'loggedin' not in session: return redirect(url_for('login'))
    cart = session.get('cart', {})
    if product_id in cart:
        cart.pop(product_id)
        session['cart'] = cart
        session.modified = True
        flash('Item removido do carrinho.', 'success')
    return redirect(url_for('cart'))
@app.route('/checkout')
def checkout():
    if 'loggedin' not in session:
        flash('Por favor, faça login para finalizar a compra.', 'info')
        return redirect(url_for('login'))
    cart = session.get('cart', {})
    if not cart:
        flash('Seu carrinho está vazio!', 'warning')
        return redirect(url_for('cart'))
    total_price = sum(item['price'] * item['quantity'] for item in cart.values())
    user_id = session['id']
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM addresses WHERE user_id = %s AND is_active = TRUE", (user_id,))
    addresses = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('checkout.html', cart_items=cart, total_price=total_price, addresses=addresses)
@app.route('/place_order', methods=['POST'])
def place_order():
    if 'loggedin' not in session or not session.get('cart'): return redirect(url_for('index'))
    user_id = session['id']
    cart = session['cart']
    total_price = sum(item['price'] * item['quantity'] for item in cart.values())
    address_id = request.form.get('address_id')
    payment_method = request.form.get('payment_method')
    subscription_plan = None
    if not address_id or not payment_method:
        flash('Por favor, selecione um endereço e uma forma de pagamento.', 'danger')
        return redirect(url_for('checkout'))
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO orders (user_id, shipping_address_id, total_amount, status) VALUES (%s, %s, %s, %s)",
                       (user_id, address_id, total_price, 'em_preparacao'))
        order_id = cursor.lastrowid
        for product_id, item in cart.items():
            if not item.get('is_subscription', False):
                cursor.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s, %s, %s, %s)",
                               (order_id, int(product_id), item['quantity'], item['price']))
                cursor.execute("UPDATE products SET stock_quantity = stock_quantity - %s WHERE id = %s",
                               (item['quantity'], int(product_id)))
            else:
                cursor.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price, product_name) VALUES (%s, NULL, %s, %s, %s)",
                               (order_id, item['quantity'], item['price'], item['name']))
                subscription_plan = item['name'].replace('Assinatura: ', '')
        if subscription_plan:
            cursor.execute("SELECT id FROM subscriptions WHERE user_id = %s AND status = 'ativa'", (user_id,))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO subscriptions (user_id, plan_name, status) VALUES (%s, %s, 'ativa')", (user_id, subscription_plan))
        conn.commit()
        cursor.close()
        conn.close()
        session.pop('cart', None)
        session.modified = True
        return redirect(url_for('order_confirmation', order_id=order_id))
    except Exception as e:
        flash(f"Ocorreu um erro ao processar seu pedido: {e}", 'danger')
        return redirect(url_for('checkout'))
@app.route('/order_confirmation/<int:order_id>')
def order_confirmation(order_id):
    if 'loggedin' not in session: return redirect(url_for('login'))
    return render_template('order_confirmation.html', order_id=order_id)

# --- ROTAS DA CONTA DO USUÁRIO ---
@app.route('/my_account', methods=['GET', 'POST'])
def my_account():
    if 'loggedin' not in session: return redirect(url_for('login'))
    user_id = session['id']
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        street = request.form['street']
        number = request.form['number']
        complement = request.form.get('complement', '')
        neighborhood = request.form['neighborhood']
        city = request.form['city']
        state = request.form['state']
        zip_code = request.form['zip_code']
        cursor.execute("INSERT INTO addresses (user_id, street, number, complement, neighborhood, city, state, zip_code) "
                       "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                       (user_id, street, number, complement, neighborhood, city, state, zip_code))
        conn.commit()
        flash('Endereço adicionado com sucesso!', 'success')
        return redirect(url_for('my_account'))
    
    cursor.execute("SELECT * FROM addresses WHERE user_id = %s AND is_active = TRUE", (user_id,))
    addresses = cursor.fetchall()
    
    cursor.execute("SELECT plan_name FROM subscriptions WHERE user_id = %s AND status = 'ativa'", (user_id,))
    subscription = cursor.fetchone()
    
    cursor.close()
    conn.close()
    return render_template('my_account.html', addresses=addresses, subscription=subscription)
@app.route('/my_orders')
def my_orders():
    if 'loggedin' not in session:
        flash('Por favor, faça login para ver seus pedidos.', 'warning')
        return redirect(url_for('login'))
    user_id = session['id']
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT o.id, o.total_amount, o.status, o.created_at, p.id as product_id, p.name as product_name, oi.quantity, oi.unit_price FROM orders AS o JOIN order_items AS oi ON o.id = oi.order_id JOIN products AS p ON oi.product_id = p.id WHERE o.user_id = %s ORDER BY o.created_at DESC", (user_id,))
        orders_raw = cursor.fetchall()
        cursor.close()
        conn.close()
        orders = {}
        for item in orders_raw:
            order_id = item['id']
            if order_id not in orders:
                orders[order_id] = {'total_amount': item['total_amount'], 'status': item['status'], 'created_at': item['created_at'], 'items': []}
            orders[order_id]['items'].append(item)
        return render_template('my_orders.html', orders=orders)
    except Exception as e:
        flash(f'Ocorreu um erro ao buscar seus pedidos: {e}', 'danger')
        return redirect(url_for('index'))
@app.route('/submit_review', methods=['POST'])
def submit_review():
    if 'loggedin' not in session:
        flash('Você precisa estar logado para enviar uma avaliação.', 'warning')
        return redirect(url_for('login'))
    try:
        user_id = session['id']
        product_id = request.form['product_id']
        order_id = request.form['order_id']
        rating = request.form['rating']
        comment = request.form.get('comment', '')
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO reviews (product_id, user_id, order_id, rating, comment) VALUES (%s, %s, %s, %s, %s)",
                       (product_id, user_id, order_id, rating, comment))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Sua avaliação foi enviada com sucesso. Obrigado!', 'success')
    except mysql.connector.Error as err:
        flash(f'Ocorreu um erro ao salvar sua avaliação: {err}', 'danger')
    return redirect(url_for('my_orders'))
@app.route('/cancel_subscription', methods=['POST'])
def cancel_subscription():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("UPDATE subscriptions SET status = 'cancelada' WHERE user_id = %s AND status = 'ativa'", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Sua assinatura foi cancelada com sucesso.', 'success')
    except mysql.connector.Error as err:
        flash(f'Ocorreu um erro ao cancelar sua assinatura: {err}', 'danger')
    return redirect(url_for('my_account'))
@app.route('/edit_address/<int:address_id>', methods=['GET', 'POST'])
def edit_address(address_id):
    if 'loggedin' not in session: return redirect(url_for('login'))
    user_id = session['id']
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        street = request.form['street']
        number = request.form['number']
        complement = request.form.get('complement', '')
        neighborhood = request.form['neighborhood']
        city = request.form['city']
        state = request.form['state']
        zip_code = request.form['zip_code']
        cursor.execute("UPDATE addresses SET street=%s, number=%s, complement=%s, neighborhood=%s, city=%s, state=%s, zip_code=%s WHERE id=%s AND user_id=%s",
                       (street, number, complement, neighborhood, city, state, zip_code, address_id, user_id))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Endereço atualizado com sucesso!', 'success')
        return redirect(url_for('my_account'))
    cursor.execute("SELECT * FROM addresses WHERE id = %s AND user_id = %s", (address_id, user_id))
    address = cursor.fetchone()
    cursor.close()
    conn.close()
    if not address:
        flash('Endereço não encontrado ou não pertence a você.', 'danger')
        return redirect(url_for('my_account'))
    return render_template('edit_address.html', address=address)
@app.route('/delete_address', methods=['POST'])
def delete_address():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    address_id = request.form.get('address_id')
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(id) as order_count FROM orders WHERE shipping_address_id = %s", (address_id,))
        result = cursor.fetchone()
        order_count = result['order_count']
        if order_count > 0:
            cursor.execute("UPDATE addresses SET is_active = FALSE WHERE id = %s AND user_id = %s", (address_id, user_id))
            flash('Endereço arquivado com sucesso! Ele não aparecerá mais como opção, mas será mantido no histórico de seus pedidos.', 'success')
        else:
            cursor.execute("DELETE FROM addresses WHERE id = %s AND user_id = %s", (address_id, user_id))
            flash('Endereço excluído com sucesso!', 'success')
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        flash(f'Ocorreu um erro ao processar sua solicitação: {err}', 'danger')
    return redirect(url_for('my_account'))

# --- ROTAS DE ADMIN ---
@app.route('/admin/orders')
@admin_required
def admin_orders():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT o.id, o.total_amount, o.status, o.created_at, u.name as customer_name FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC")
        orders = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('admin/admin_orders.html', orders=orders)
    except Exception as e:
        flash(f"Ocorreu um erro ao buscar os pedidos: {e}", "danger")
        return redirect(url_for('index'))
@app.route('/admin/order/update_status/<int:order_id>', methods=['POST'])
@admin_required
def update_order_status(order_id):
    status = request.form.get('status')
    if not status:
        flash("Status inválido.", "danger")
        return redirect(url_for('admin_orders'))
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("UPDATE orders SET status = %s WHERE id = %s", (status, order_id))
        conn.commit()
        cursor.close()
        conn.close()
        flash(f"Status do pedido #{order_id} atualizado com sucesso!", "success")
    except Exception as e:
        flash(f"Erro ao atualizar o status: {e}", "danger")
    return redirect(url_for('admin_orders'))
@app.route('/admin/products')
@admin_required
def admin_products():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products ORDER BY id DESC")
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('admin/admin_products.html', products=products)
@app.route('/admin/products/add', methods=['GET', 'POST'])
@admin_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        stock_quantity = request.form['stock_quantity']
        image_url = request.form.get('image_url', '')
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO products (name, description, price, stock_quantity, image_url) VALUES (%s, %s, %s, %s, %s)",
                       (name, description, price, stock_quantity, image_url))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Produto adicionado com sucesso!', 'success')
        return redirect(url_for('admin_products'))
    return render_template('admin/admin_product_form.html', title="Adicionar Novo Produto")
@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        stock_quantity = request.form['stock_quantity']
        image_url = request.form.get('image_url', '')
        cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, stock_quantity=%s, image_url=%s WHERE id=%s",
                       (name, description, price, stock_quantity, image_url, product_id))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Produto atualizado com sucesso!', 'success')
        return redirect(url_for('admin_products'))
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('admin/admin_product_form.html', title="Editar Produto", product=product)
@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Produto excluído com sucesso!', 'success')
    except mysql.connector.Error as err:
        flash(f'Erro ao excluir o produto. Ele pode estar associado a um pedido existente. Erro: {err}', 'danger')
    return redirect(url_for('admin_products'))
@app.route('/admin/subscriptions')
@admin_required
def admin_subscriptions():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT s.id, s.plan_name, s.status, s.created_at, u.name as customer_name FROM subscriptions s JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC")
        subscriptions = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('admin/admin_subscriptions.html', subscriptions=subscriptions)
    except Exception as e:
        flash(f"Ocorreu um erro ao buscar as assinaturas: {e}", "danger")
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)