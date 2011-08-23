import logging
import sqlite3
import os.path
import time

import check_nvd_correctness
import nvdparser


logger = logging.getLogger("svdb.nvd.db")
logger.setLevel(logging.INFO)


class DB(object):
    """DB layer
    """
    #DB state
    NEW_DB_CREATED = 0
    DB_EXISTS = 1
    
    
    @classmethod
    def init(cls, db_path='vuln.sqlite'):
        cls._db_path = db_path
        tables_not_exists = not os.path.exists(cls._db_path)
        
        cls._con = sqlite3.connect(cls._db_path)
        cls._cur = cls._con.cursor()
        
        if tables_not_exists:
            logger.info("Created clean DB: %s" % os.path.abspath(cls._db_path))
            
            tables = [
                ("vulnerabilities", """
                            ID INTEGER PRIMARY KEY AUTOINCREMENT, 
                            cve_id TEXT UNIQUE, 
                            summary TEXT, 
                            security_protection TEXT, 
                            vuln_date DATETIME, 
                            score DOUBLE, 
                            access_vector TEXT,  
                            access_complexity TEXT, 
                            authentication TEXT, 
                            confidentiality_impact TEXT, 
                            integrity_impact TEXT, 
                            availability_impact TEXT
                            """),
                ("products","""
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            part TEXT, 
                            vendor TEXT, 
                            product TEXT, 
                            official_name TEXT, 
                            ports TEXT
                            """),
                ("concrete_products","""
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            product_id INTEGER,
                            version TEXT, 
                            pr_update TEXT, 
                            edition TEXT, 
                            language TEXT
                            """),
                ("products_to_vulnerabilities","""
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            concrete_product_id INTEGER,
                            vuln_id INTEGER
                            """),
                ("vulnerabilities_to_predicates","""
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            vuln_id INTEGER,
                            predict TEXT
                            """)
                ]
            
            for table in tables:
                cls._cur.execute("create table %s(%s)" % table)
            logger.info("Created DB tables: %s" % ", ".join([table[0] for table in tables]))
            
            sql = """CREATE INDEX cve_id_index ON vulnerabilities (cve_id)"""
            cls._cur.execute(sql)

            sql = """CREATE INDEX vuln_id ON products_to_vulnerabilities (vuln_id)"""
            cls._cur.execute(sql)
            
            sql = """CREATE INDEX concrete_product_id ON products_to_vulnerabilities (concrete_product_id)"""
            cls._cur.execute(sql)
            
            sql = """CREATE INDEX products_index ON products (part, vendor, product)"""
            cls._cur.execute(sql)
            
            sql = """CREATE INDEX concrete_products_index ON concrete_products (product_id)"""
            cls._cur.execute(sql)
            
            return cls.NEW_DB_CREATED
        else:
            logger.info("Opened DB: %s" % os.path.abspath(cls._db_path))
            return cls.DB_EXISTS
        
        
    @classmethod
    def add_entry(cls, vuln_entry):
        
        sql = """INSERT INTO vulnerabilities (cve_id, summary, security_protection, vuln_date, 
        score, access_vector, access_complexity, authentication, 
        confidentiality_impact, integrity_impact, availability_impact) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"""
        
        try:
            cls._cur.execute(sql,
             (str(vuln_entry.cve), 
              vuln_entry.summary.replace("'", "''"),
              str(vuln_entry.cvss_base_metrics.security_protection),
              str(vuln_entry.published_datetime),
              vuln_entry.cvss_base_metrics.score,
              str(vuln_entry.cvss_base_metrics.access_vector),
              str(vuln_entry.cvss_base_metrics.access_complexity),
              str(vuln_entry.cvss_base_metrics.authentication),
              str(vuln_entry.cvss_base_metrics.confidentiality_impact),
              str(vuln_entry.cvss_base_metrics.integrity_impact),
              str(vuln_entry.cvss_base_metrics.availability_impact)))
        except sqlite3.IntegrityError:
            #TODO: we need clean all associated data and after add new data
            return
            
            sql = """UPDATE vulnerabilities SET 
            summary = ?, 
            security_protection = ?, 
            vuln_date = ?, 
            score = ?, 
            access_vector = ?, 
            access_complexity = ?, 
            authentication = ?, 
            confidentiality_impact = ?, 
            integrity_impact = ?, 
            availability_impact = ?
            WHERE cve_id = ?"""
            
            cls._cur.execute(sql,
             ( vuln_entry.summary.replace("'", "''"),
              str(vuln_entry.cvss_base_metrics.security_protection),
              str(vuln_entry.published_datetime),
              vuln_entry.cvss_base_metrics.score,
              str(vuln_entry.cvss_base_metrics.access_vector),
              str(vuln_entry.cvss_base_metrics.access_complexity),
              str(vuln_entry.cvss_base_metrics.authentication),
              str(vuln_entry.cvss_base_metrics.confidentiality_impact),
              str(vuln_entry.cvss_base_metrics.integrity_impact),
              str(vuln_entry.cvss_base_metrics.availability_impact),
              str(vuln_entry.cve)))
        
        
        vuln_id = cls._cur.lastrowid
        
        sql = """INSERT INTO vulnerabilities_to_predicates (vuln_id, predict) VALUES (?, ?);"""
        cls._cur.execute(sql, (vuln_id, str(vuln_entry.condition)))
        
        
        for cpeid in vuln_entry.products:
            sql = """SELECT ID FROM products WHERE part = ? AND vendor = ? AND product = ?;"""
            res = cls._cur.execute(sql, (cpeid.get_part_info(), 
                                   cpeid.get_vendor_info(),
                                   cpeid.get_product_info())).fetchall()
            len_res = len(res)
            if len_res > 1:
                logger.info("Multiple %s" % cpeid.get_base_cpeid())
            elif len_res == 1:   
                product_id = res[0][0]
            #If product is absence
            else:
                sql = """INSERT INTO products (part, vendor, product) VALUES (?, ?, ?);"""
                
                cls._cur.execute(sql, (cpeid.get_part_info(), 
                                   cpeid.get_vendor_info(),
                                   cpeid.get_product_info()))
                
                product_id = cls._cur.lastrowid
                
            sql = """SELECT ID FROM concrete_products WHERE ID = ? AND version = ? AND pr_update = ? 
            AND edition = ? AND language = ?;"""
            res = cls._cur.execute(sql, (product_id, 
                                   cpeid.get_version_info(),
                                   cpeid.get_update_info(),
                                   cpeid.get_edition_info(),
                                   cpeid.get_language_info())).fetchall()
            
            len_res = len(res)
            if len_res > 1:
                logger.info("Multiple %s" % cpeid)
            elif len_res == 1:   
                concrete_product_id = res[0][0]
            #If concrete product is absence
            else:
                sql = """INSERT INTO concrete_products (product_id, version, pr_update, edition, language) 
                VALUES (?, ?, ?, ?, ?);"""
                
                cls._cur.execute(sql, (product_id, 
                                   cpeid.get_version_info(),
                                   cpeid.get_update_info(),
                                   cpeid.get_edition_info(),
                                   cpeid.get_language_info()))
                
                concrete_product_id = cls._cur.lastrowid

            
            sql = """INSERT INTO products_to_vulnerabilities (concrete_product_id, vuln_id) VALUES (?, ?);"""
            
            cls._cur.execute(sql, (concrete_product_id, vuln_id))
        
        
    @classmethod
    def finalize(cls):
        cls._con.commit()
        cls._con.close()
        logger.info("DB % s closed" % os.path.abspath(cls._db_path))
        

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s  %(levelname)-8s %(name)-25s %(message)s', datefmt='%H:%M')
    
    try:
        os.remove('vuln.sqlite')
    except:
        pass
    
    
    logger.info("Begin database creating")
    
    begin_time_sec = time.time()
    
    DB.init()
    
    check_nvd_correctness.check_correctness(os.environ['KAFTI_NVD_BASES_PATH'])
    
    
    good_nvd_entries_counter = 0
    bad_nvd_entries_counter = 0

    nvd_dir = os.environ['KAFTI_NVD_BASES_PATH']
    for file in os.listdir(nvd_dir):
        if file.startswith('nvd'):
            fullname = os.path.join(nvd_dir, file)
            for vulnObject in nvdparser.parse_nvd_file(fullname, 
                                                       check_nvd_correctness.bad_cve_id_list):
                if vulnObject is None:
                    bad_nvd_entries_counter += 1
                else:
                    #entry is good
                    good_nvd_entries_counter += 1
                    
                    DB.add_entry(vulnObject)
    

    logger.info("Database creating done, takes %s sec" % (time.time() - begin_time_sec))
    logger.info("Bad nvd entries count = %s" % bad_nvd_entries_counter)
    logger.info("Good nvd entries count = %s" % good_nvd_entries_counter)
    
    
    DB.finalize()