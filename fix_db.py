#!/usr/bin/env python3
"""
fix_db.py  —  Fixes a corrupted or missing database.
Deletes the old database and creates a fresh one with all guards,
sites, and the default admin account.

Usage:  py fix_db.py
"""
import sqlite3, os, hashlib, secrets, uuid

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)
DB_PATH  = os.path.join(DATA_DIR, "data", "security.db")

os.makedirs(os.path.join(DATA_DIR, "data"), exist_ok=True)

# Remove old/corrupt database
for f in [DB_PATH, DB_PATH + "-journal", DB_PATH + "-wal", DB_PATH + "-shm"]:
    if os.path.exists(f):
        os.remove(f)
        print(f"  Removed: {f}")

print("  Creating fresh database...")
conn = sqlite3.connect(DB_PATH)

conn.executescript("""
    CREATE TABLE admins (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
        password_hash TEXT NOT NULL, salt TEXT NOT NULL,
        role TEXT DEFAULT 'manager', active INTEGER DEFAULT 1,
        last_login TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE UNIQUE INDEX admins_email ON admins(email);
    CREATE TABLE guards (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, license_number TEXT,
        base_rate REAL DEFAULT 0, phone TEXT, email TEXT, notes TEXT,
        active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE sites (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, client_name TEXT NOT NULL,
        address TEXT, default_rate REAL DEFAULT 0, contact_name TEXT,
        contact_phone TEXT, active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE rates (
        guard_id TEXT, site_id TEXT, rate REAL NOT NULL,
        PRIMARY KEY (guard_id, site_id));
    CREATE TABLE submissions (
        id TEXT PRIMARY KEY, guard_id TEXT NOT NULL, site_id TEXT NOT NULL,
        shift_date TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL,
        total_hours REAL NOT NULL, notes TEXT, photo_filename TEXT,
        status TEXT DEFAULT 'pending', admin_note TEXT, reviewed_by TEXT,
        submitted_at TEXT DEFAULT CURRENT_TIMESTAMP, reviewed_at TEXT);
    CREATE TABLE reminders (
        id TEXT PRIMARY KEY, guard_id TEXT NOT NULL, message TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP, seen_at TEXT);
    CREATE TABLE audit_log (
        id TEXT PRIMARY KEY, admin_id TEXT, admin_name TEXT,
        action TEXT NOT NULL, details TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
""")
conn.commit()

# Default superadmin
ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL",    "admin@brownowlsecurity.com.au")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
ADMIN_NAME     = os.environ.get("ADMIN_NAME",     "Super Admin")

def hash_password(pw, salt=None):
    if not salt: salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000)
    return h.hex(), salt

h, salt = hash_password(ADMIN_PASSWORD)
conn.execute(
    "INSERT INTO admins (id,name,email,password_hash,salt,role) VALUES (?,?,?,?,?,'superadmin')",
    (str(uuid.uuid4()), ADMIN_NAME, ADMIN_EMAIL, h, salt))
conn.commit()
print(f"  Admin created: {ADMIN_EMAIL}")

GUARDS = [['2d342469-3dba-4f51-a46f-8a78fe02beac', 'Aaditya Sihag', '', 0.0, '', '', ''], ['7005cd3a-42e4-4bb7-8b66-d3963527ce7e', 'Aaliyan Mehmood', '', 0.0, '', '', ''], ['d61a7f71-79d1-43a7-85da-67d0a42e6245', 'Ahmed Khalid Ilyas', '', 0.0, '', '', ''], ['aff7ccee-6b27-473c-afeb-516af7d36024', 'Ahmet Oguzhan Uysal', '', 0.0, '', '', ''], ['7c226439-ae33-441e-93ca-bd4125cc053f', 'Aitazaz Ahsan', '', 0.0, '', '', ''], ['b5ae2cb1-3902-4fe4-b9ec-81675f9e211e', 'Alan Doski', '', 0.0, '', '', ''], ['7ace1455-d70d-4c23-8b87-31e9080390c3', 'Ali Hussaini', '', 0.0, '', '', ''], ['371461ef-b89c-42ed-9a99-936d44e52da6', 'Amaan Husaain', '', 0.0, '', '', ''], ['f6242e11-2cb4-4c14-a6e7-9838fa2d1908', 'Ammad Hassan', '', 0.0, '', '', ''], ['40de2da3-e888-44cd-a484-78dad853ecd1', 'Arjunveer Parmar', '', 0.0, '', '', ''], ['0493f2ab-8f99-49ae-8d9a-187616c011fa', 'Asad ullah Saleem', '', 0.0, '', '', ''], ['4872c2f9-e5db-42da-8e21-b13ae5fec475', 'Ashish Kumar', '', 0.0, '', '', ''], ['13b7d517-1cf1-415a-a592-d91964e15592', 'Awis Kakar', '', 0.0, '', '', ''], ['93e73380-a477-40c4-9732-b5652d611708', 'Azan Syed', '', 0.0, '', '', ''], ['f7321c24-20f5-40ac-807f-40afefe4c50a', 'Chirag Mehta', '', 0.0, '', '', ''], ['56eaac45-0966-406a-bb54-a2a0fe8a7af2', 'Chris Peniamina Kalauati', '', 0.0, '', '', ''], ['f6bb964d-fa18-4413-9d88-1899b5dd24d3', 'Darooj Karmani', '', 0.0, '', '', ''], ['f25b8ae0-3ed3-4ff9-81f5-1a0c3e932d72', 'David Alyas', '', 0.0, '', '', ''], ['2606c75f-2997-4455-ab9c-3d260bc445bf', 'Elias Baghdan', '', 0.0, '', '', ''], ['f6463b4b-767c-4bc5-b1ea-09f594671678', 'Faizan Ahmed', '', 0.0, '', '', ''], ['015959ed-eac8-4ab5-af7d-92dcdd9b86aa', 'Faizan Ahmed Tk', '', 0.0, '', '', ''], ['e48a17e0-2b50-43ff-a5fc-b490e67783b4', 'Georges Zaya', '', 0.0, '', '', ''], ['97decd7d-d570-4ec9-b26b-74dc739d3daa', 'Georgyo Kouifatie', '', 0.0, '', '', ''], ['64e75957-8ed9-42ec-ad24-11adf6c56dca', 'Hajar Golzarmalake', '', 0.0, '', '', ''], ['99c61635-30bc-4073-b466-e0e625b1d0ef', 'Hamza Rassy', '', 0.0, '', '', ''], ['a72e3461-94de-42d3-a12d-28f0a823e5cc', 'Harmanjot Singh', '', 0.0, '', '', ''], ['903d811c-b267-4893-8e66-acedfe254581', 'Harshdeep Singh', '', 0.0, '', '', ''], ['b4d1b0c8-dc31-4d83-b9cc-9b03e0263d3f', 'Hassan Amir', '', 0.0, '', '', ''], ['4297b4cb-2860-4233-86cc-8149678fe654', 'Hilal Isik', '', 0.0, '', '', ''], ['3785db58-cbfa-4f27-88f3-6a838e9f26c3', 'Huzaifa Qureshi', '', 0.0, '', '', ''], ['caee8ccb-cd3e-40c3-9f11-060c5e2964fd', 'Imran Eren', '', 0.0, '', '', ''], ['2d5b6f62-22dd-4725-85c2-a5b8f6a74025', 'Ishtiyaq Ahmed', '', 0.0, '', '', ''], ['a044613e-6bd9-4246-a3ea-c2634ea294ed', 'Israfil Sahin', '', 0.0, '', '', ''], ['93b7627a-85b8-4407-b4ba-e858b20abc00', 'Jaiveer Bhullar', '', 0.0, '', '', ''], ['24c17c92-4724-463c-be6a-a1a11c803a57', 'Jamil Asraf Srabon', '', 0.0, '', '', ''], ['762a33a5-e86a-4532-b74a-fc18bd4244b1', 'Jane Williams', 'SG789012', 36.5, '', '', ''], ['74cdd7b2-aa47-4ed8-be3c-e36f667f3d7e', 'Jansher Khan', '', 0.0, '', '', ''], ['3caea604-e452-42a6-bfdb-8e2e0a702849', 'Jasvir Sarai', '', 0.0, '', '', ''], ['aca73463-0b05-4e53-ad24-dcd9b7d0091a', 'Jitender Singh', '', 0.0, '', '', ''], ['921ce509-d813-46fc-947a-2adf58ff06cc', 'Jobaydur Rahman', '', 0.0, '', '', ''], ['g1', 'John Smith', 'SG123456', 35.0, '', '', ''], ['3624ba66-a28f-464d-a2b1-afdeb3395d73', 'Joseph Greige', '', 0.0, '', '', ''], ['aad31077-eba7-4a6d-9210-56b45f3ca049', 'Julius Malakha', '', 0.0, '', '', ''], ['aae1dd35-f3fe-4cfc-81a4-2264c024aaef', 'Justin L Elzaibak', '', 0.0, '', '', ''], ['599f9486-10fd-47c6-a2fd-6e2c680572e4', 'Kartikay Sharma', '', 0.0, '', '', ''], ['c86ff73b-989d-4231-bee2-ee6749f994ea', 'MD Sabbir Hossain', '', 0.0, '', '', ''], ['56c4fb83-eeef-4f21-b361-b1ec7e1c02f2', 'Maisam Akbari', '', 0.0, '', '', ''], ['2b0a929a-1cf7-45b8-a119-4a0edacaeb4f', 'Maninderjeet Singh', '', 0.0, '', '', ''], ['b371bfc4-cc10-4a4a-8f5d-652cef72707e', 'Mohamed Abdul-Kadir Hassan', '', 0.0, '', '', ''], ['00ad09b9-7bd0-4753-8709-b72ba1adbc27', 'Mohammad Shafai', '', 0.0, '', '', ''], ['a11172b5-2db4-49cc-862b-fee488dbe027', 'Mohammad Sultan', '', 0.0, '', '', ''], ['1578d35b-7142-4682-a31f-e8b5b1c6aba3', 'Mohammed Shayaq Ali Shahabaz', '', 0.0, '', '', ''], ['a0716270-30c2-4648-b305-890ce4a6ca09', 'Mudassar Habib', '', 0.0, '', '', ''], ['4185efed-75a4-4361-a1d6-0a431d3c33bf', 'Muhammad Ansari', '', 0.0, '', '', ''], ['3fce74c4-df04-4017-a602-0c05335b4a2b', 'Muhammad Hamayoon', '', 0.0, '', '', ''], ['095da750-38a0-4193-93fd-7f16d7212db7', 'Muhammad Shoaib Bin Zahid', '', 0.0, '', '', ''], ['8b929599-9942-4030-a480-512bf1c6e814', 'Muhammad Wasim Qureshi', '', 0.0, '', '', ''], ['ee263dbb-1172-4d6a-b905-e7a7e391c8c2', 'Muhammed Gun', '', 0.0, '', '', ''], ['d995c525-ca36-4e2c-8cfb-c47272c950fa', 'Murat Cosar', '', 0.0, '', '', ''], ['8945c842-cf80-4eda-bfb7-e8984b774454', 'Musa Kaya', '', 0.0, '', '', ''], ['769748d5-3e80-416a-a40f-632ff22f2658', 'Nadeem Mohammed', '', 0.0, '', '', ''], ['dabb203e-76ae-4855-9976-8d3b7695cd69', 'Nazhim Kalam', '', 0.0, '', '', ''], ['9d3fae79-f73a-4240-8874-60b6c86f6961', 'Nikhil Goyal', '', 0.0, '', '', ''], ['14a5017e-4573-4344-a03c-00b3a7397bbf', 'Noshad Muzaffar', '', 0.0, '', '', ''], ['dee8ba7c-7a4c-47d3-9dd6-22af61dc6efc', 'Nuthara Amarasingha', '', 0.0, '', '', ''], ['017b2318-ce49-4585-9270-987d3c46b64c', 'Omar Khan', '', 0.0, '', '', ''], ['19d79e25-f987-4ac4-a190-48607fb6b61e', 'Paras Nandal', '', 0.0, '', '', ''], ['c5cf1f17-4934-4c1d-af61-db747254ed7f', 'Pardeep Bawa', '', 0.0, '', '', ''], ['f6ef4eb4-848f-49e0-bb88-af08861caa76', 'Pardeep Kumar', '', 0.0, '', '', ''], ['a17c2a01-ec95-480b-b1be-a3f7a7f75c69', 'Pardeep Singh', '', 0.0, '', '', ''], ['623e9e58-ca46-4627-800d-b6e8fa77af44', 'Parmeet Singh', '', 0.0, '', '', ''], ['df30a967-d974-46db-bb4e-c3b20939501d', 'Parmjeet Chatrath', '', 0.0, '', '', ''], ['b4801144-f7da-482a-a5b9-3692181176d9', 'Pratham Kaushal', '', 0.0, '', '', ''], ['19998317-7daf-4651-bff1-2c905e7091af', 'Qasim Rehan', '', 0.0, '', '', ''], ['8c7c98e2-32d6-4ea7-a5a4-a660e78c2a85', 'Qudsiya Malik', '', 0.0, '', '', ''], ['cc656fda-58b1-4114-afc1-c9d84a4e01fe', 'Rahim Uddin', '', 0.0, '', '', ''], ['f8cf4580-92bf-4dee-90ce-eb9b757e2966', 'Rahul Kumar', '', 0.0, '', '', ''], ['51dd8a35-3f0f-456e-ab6f-7396a0a6e542', 'Raja Noman', '', 0.0, '', '', ''], ['fa6a3f1b-42e0-40e5-84ce-e14f89ddf9ea', 'Rajat Sharma', '', 0.0, '', '', ''], ['1fc6d146-5c01-4057-b308-040c2ad5f8e6', 'Rakan Ali Alsaihati', '', 0.0, '', '', ''], ['64d89485-8ac9-46c3-82c8-e5e7a49df6fe', 'Rohaib Hassan Shah', '', 0.0, '', '', ''], ['d6ab0567-3622-42d9-af3d-42ea0e795bba', 'Rohit Mahindru', '', 0.0, '', '', ''], ['c8991a54-e9df-4771-9a1f-9e885fcbe0b8', 'Sadia Khandakar Eshita', '', 0.0, '', '', ''], ['896557c6-832b-4b90-bae8-155ea0f915d3', 'Sahil Sahil', '', 0.0, '', '', ''], ['9454c8b1-f57a-429f-9a7c-c7ba258835c5', 'Sahil Z82-509-90S', '', 0.0, '', '', ''], ['312acd6d-a455-4830-b046-c0a92a64bef4', 'Saied Shohani', '', 0.0, '', '', ''], ['6d7686aa-5514-4266-b31f-bcf29b0608f2', 'Salvatore Francesico Ozzimo', '', 0.0, '', '', ''], ['fba40599-dfb9-4012-902f-a0c8511161ec', 'Satwinder Goraya', '', 0.0, '', '', ''], ['0ea69a04-57ac-4cf8-ba74-08c9e019eaa7', 'Sehenur Shanto', '', 0.0, '', '', ''], ['7fb974a4-8d3c-4e76-92e8-5cfb73d9a086', 'Sejal Wahi', '', 0.0, '', '', ''], ['6da3ded3-171f-4071-8573-9b3450cb8c1a', 'Shaheryar Shah', '', 0.0, '', '', ''], ['1ab274d4-e5be-4500-a8f6-936c9dc868e5', 'Shahriyar Khan', '', 0.0, '', '', ''], ['51ea1de8-99b2-4fa1-85fa-f26e1995667b', 'Shakir Sohail', '', 0.0, '', '', ''], ['827a474c-4f61-43dd-837b-00496af9ec44', 'Sheraz Ahmed', '', 0.0, '', '', ''], ['f84ceda8-9dfe-4fd4-a987-dac9d91028ee', 'Sukhrajdeep Singh', '', 0.0, '', '', ''], ['2dec97ad-4487-425d-a516-e5f2264eb602', 'Surender Berwal', '', 0.0, '', '', ''], ['edb8ddf9-87b6-4f91-a4be-7bed924f6df2', 'Talha Kolcak', '', 0.0, '', '', ''], ['edb8bf2f-2bf0-4a38-ac4c-303ab7f7661d', 'Usama Iqbal', '', 0.0, '', '', ''], ['675ce8c5-058a-417f-8221-b7eef8454d7d', 'Usama Riaz', '', 0.0, '', '', ''], ['e3ab9bb7-62cd-4c0a-8731-acb6f33d44a3', 'Usama arif Khan Niazi', '', 0.0, '', '', ''], ['212f0de7-e416-4464-ad0d-e8636944e564', 'Vivek Shukla', '', 0.0, '', '', ''], ['5c0c650c-f504-4e74-a030-527f01cf60bc', 'Yousif Abed', '', 0.0, '', '', ''], ['c9f80438-8198-41e4-8450-5ab85c3f591b', 'Youssef Habib', '', 0.0, '', '', ''], ['57e38ba1-538d-4ac0-976b-f1426974d55a', 'Yusuf Barwary', '', 0.0, '', '', ''], ['d8a5cf43-15af-4f64-9b49-2bded1fecc6f', 'Zacharia Najib', '', 0.0, '', '', ''], ['8f3de9d1-28e0-49ca-8bfb-c65aa84db2fd', 'Zaid Mohsin Mohammed', '', 0.0, '', '', ''], ['c9736ead-6d82-40dd-9cb3-fa27057b5f1b', 'Zamin Rezai', '', 0.0, '', '', ''], ['1adccdd6-e81a-416b-9dd9-a05e79c62fd5', 'Zubair Mohammed', '', 0.0, '', '', '']]

SITES  = [['0e9fef5e-d570-46b9-8905-ff714e3ea66f', 'Anglers Tavern', 'Prime VIC', '', 0.0, '', ''], ['5b14397b-f017-4300-8633-8c8a0a56c645', 'Apollo Bay', 'Prime VIC', '', 0.0, '', ''], ['27ebb7c7-bf14-4fab-9543-271f4c20193d', 'Ball Court Hotel', 'Prime VIC', '', 0.0, '', ''], ['39351cfe-2c0b-4a79-9a45-6cb3a7e3461f', 'Bearbrass', 'Prime VIC', '', 0.0, '', ''], ['0659bcca-4f34-4135-ba32-c9de7192aa08', 'Beer Deluxe Fed Square', 'Prime VIC', '', 0.0, '', ''], ['e22f35e5-c3db-42e0-8dce-6ac320e0d16f', 'Blackbird Melbourne', 'Prime VIC', '', 0.0, '', ''], ['c8e99fd2-a59c-400d-8099-09e7b0f12cbb', 'Byblós Melbourne', 'Prime VIC', '', 0.0, '', ''], ['e7cf5239-08ab-4394-87b4-7d15dbd2e490', 'Camden Hotel', 'Prime VIC', '', 0.0, '', ''], ['7cf6d102-0f95-4407-8afe-8d1ca5d55508', 'Chadstone Shopping Centre', 'Prime VIC', '', 0.0, '', ''], ['adec7846-c667-4811-95db-396361fb8da2', 'Cosy Corner Beach', 'Prime VIC', '', 0.0, '', ''], ['9325d233-2972-462b-9848-db76c7f6bf1f', 'Crossguard - Three Blue Ducks, Melbourne', 'Prime VIC', '', 0.0, '', ''], ['1d4e6c6b-81a3-4d5e-a171-bf4ffe2dec5e', 'Curtin House - The Toff', 'Prime VIC', '', 0.0, '', ''], ['71c63aac-4119-4b31-84c8-f45c719c5bfa', 'Death & Co Melbourne', 'Prime VIC', '', 0.0, '', ''], ['43a91075-b0fc-41a2-b442-fdf4ca75f9a1', 'Doutta Galla Hotel', 'Prime VIC', '', 0.0, '', ''], ['7628bcc6-ad26-43d7-a010-1238bf65abba', 'Eureka Hotel', 'Prime VIC', '', 0.0, '', ''], ['2595312f-df92-44ac-b592-bcea6a53cded', 'FiftyFive', 'Prime VIC', '', 0.0, '', ''], ['a6461bf0-0814-447c-b728-8d5be55511ef', 'Gardiner Hotel', 'Prime VIC', '', 0.0, '', ''], ['67453553-7fdf-455e-a0f7-6c9e11d249ca', "Harvey's Sports Bar & Grill", 'Prime VIC', '', 0.0, '', ''], ['7f1a904f-615e-4df2-854a-a9155a21c4f5', 'Hilton Melbourne Little Queen Street', 'Prime VIC', '', 0.0, '', ''], ['c2a67214-201a-4909-b83f-deda7112ae50', 'Holliava', 'Prime VIC', '', 0.0, '', ''], ['cbcc1ed7-e9d0-4d6f-8849-5875380e5cba', 'Hophaus', 'Prime VIC', '', 0.0, '', ''], ['ab088ab9-04a0-4208-b9f5-5a980e63627f', 'Hopscotch', 'Prime VIC', '', 0.0, '', ''], ['aebc7dbf-1f51-4368-b4e9-a4bbfe8d55d8', 'Hotel Esplanade', 'Prime VIC', '', 0.0, '', ''], ['ce70c75a-edc4-4523-af3b-1025302beaee', 'Kindred Studios', 'Prime VIC', '', 0.0, '', ''], ['2b85448d-b9b3-432e-8d97-b60e470f7014', 'Lakeside Pavilion', 'Prime VIC', '', 0.0, '', ''], ['adb2e470-a82c-464b-a3ea-feebaa83a043', 'Ludlow', 'Prime VIC', '', 0.0, '', ''], ['s1', 'Main Entrance', 'ABC Shopping Centre', '123 Main St, Sydney', 38.0, '', ''], ['9e09b3ae-6217-4cce-8dc5-5b2f4115eb2d', 'Main Gate', 'Westfield Sydney', '100 Market St', 38.0, '', ''], ['1f5299a8-3494-464e-8dd6-a7c90692c5d3', 'Melbourne Public', 'Prime VIC', '', 0.0, '', ''], ['aeabad4f-a0cc-40f7-a8ad-6b9cdbb91506', "PJ O'Brien's Southbank", 'Prime VIC', '', 0.0, '', ''], ['85744eae-f955-4146-9d1d-3e78b2998da0', 'Perseverance', 'Prime VIC', '', 0.0, '', ''], ['615abe54-02e6-43a0-bf91-931459aa9885', 'Public House', 'Prime VIC', '', 0.0, '', ''], ['08a584a4-ffbb-43b9-9a18-cadfee9e0038', 'Quarterhouse', 'Prime VIC', '', 0.0, '', ''], ['8a24c83b-2a2b-456b-8075-0c96105b7167', 'RSL on Bell', 'Prime VIC', '', 0.0, '', ''], ['d064a9c3-2cb7-417a-8717-f49764d25695', "River's Edge", 'Prime VIC', '', 0.0, '', ''], ['da11dda0-4646-44da-8947-dacdc86469d6', 'State of Grace', 'Prime VIC', '', 0.0, '', ''], ['8517b687-2e6c-4ea5-b11e-4ba48c08b24e', 'Studley Park Boathouse', 'Prime VIC', '', 0.0, '', ''], ['59c97e46-f587-41a0-a39e-54d0ec856d2e', 'Swan Hotel', 'Prime VIC', '', 0.0, '', ''], ['d05e6951-8e27-40e9-b276-927bde0ebb29', 'Temperance', 'Prime VIC', '', 0.0, '', ''], ['d38577cd-ad8f-4706-8553-4993a4fd8e7f', 'Terminus Hotel - Abbotsford', 'Prime VIC', '', 0.0, '', ''], ['78db70cf-6ac2-4df5-9467-641926709f8a', 'The Continental Sorrento', 'Prime VIC', '', 0.0, '', ''], ['f52761a7-e5d3-426e-8622-6ac2ab1dc903', 'The Esplanade', 'Prime VIC', '', 0.0, '', ''], ['9e4128e4-3779-4e33-a1b2-68c7d4cce964', 'The Exchange Hotel', 'Prime VIC', '', 0.0, '', ''], ['6de9d668-622d-4191-addd-466dbfb44ad0', 'The Local Port', 'Prime VIC', '', 0.0, '', ''], ['cdb5d6d6-7cac-43a5-8610-cb5345d0bb56', 'The Lyall Hotel', 'Prime VIC', '', 0.0, '', ''], ['42d36ec4-6a33-43eb-b956-30638736b643', 'The Oxford Scholar', 'Prime VIC', '', 0.0, '', ''], ['da151d9b-2ff5-4a75-9819-d1a627e76d3b', 'The Prince Hotel', 'Prime VIC', '', 0.0, '', ''], ['7f9c4373-cfc0-4aa8-9526-a30f423ac289', 'The Provincial Hotel', 'Prime VIC', '', 0.0, '', ''], ['04ef1987-9e2b-4da9-9aac-556fed8e4a78', 'The Victoria Hotel Yarraville', 'Prime VIC', '', 0.0, '', ''], ['30f65f1c-50b2-4f42-ba8a-4053c357620a', 'The Wild Geese Hotel', 'Prime VIC', '', 0.0, '', ''], ['7f9a3083-a908-4702-bc52-98ce68b39570', 'The Windsor Alehouse', 'Prime VIC', '', 0.0, '', ''], ['92a3b5b2-0c06-4b76-b223-20d83a2d4cf5', 'Trinket Bar', 'Prime VIC', '', 0.0, '', ''], ['9441f564-f27e-450b-8002-3b73b1cc169a', 'Turf Sports Bar', 'Prime VIC', '', 0.0, '', ''], ['8f8ca1fa-5a00-462d-aaaf-edc611b3829c', 'Village Belle', 'Prime VIC', '', 0.0, '', ''], ['4548c478-ace4-43f8-b884-675a38daf3e7', 'West Beach Pavilion', 'Prime VIC', '', 0.0, '', ''], ['96f6faca-0cb1-4b35-9f2a-023de1d1f5c9', 'Wharf Hotel', 'Prime VIC', '', 0.0, '', ''], ['d8a783ba-770f-4389-95a9-16a1166bc118', 'Workshop Bar', 'Prime VIC', '', 0.0, '', ''], ['7ffdd45a-de53-4a73-be11-b935e66d7189', 'Yarra Botanica', 'Prime VIC', '', 0.0, '', ''], ['2a81d6c5-4adb-4fc0-9313-e2190ea4245d', 'Yarra Valley Grand Hotel', 'Prime VIC', '', 0.0, '', ''], ['eda101b3-c0a1-4c0e-9d5d-8bc2498dbc26', 'ZIMMERMANN Chadstone', 'Prime VIC', '', 0.0, '', '']]

print(f"  Seeding {len(GUARDS)} guards...")
for g in GUARDS:
    conn.execute(
        "INSERT OR IGNORE INTO guards (id,name,license_number,base_rate,phone,email,notes) VALUES (?,?,?,?,?,?,?)",
        g)

print(f"  Seeding {len(SITES)} sites...")
for s in SITES:
    conn.execute(
        "INSERT OR IGNORE INTO sites (id,name,client_name,address,default_rate,contact_name,contact_phone) VALUES (?,?,?,?,?,?,?)",
        s)

conn.commit()

total_g = conn.execute("SELECT COUNT(*) FROM guards WHERE active=1").fetchone()[0]
total_s = conn.execute("SELECT COUNT(*) FROM sites  WHERE active=1").fetchone()[0]
conn.close()

print()
print(f"  ✓ Guards loaded:  {total_g}")
print(f"  ✓ Sites loaded:   {total_s}")
print(f"  ✓ Admin account:  {ADMIN_EMAIL} / password: {ADMIN_PASSWORD}")
print()
print("  Database is ready. Now run:  py server.py")
