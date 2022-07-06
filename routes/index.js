var express = require('express');
var router = express.Router();
var mysql = require('mysql');
var bcrypt = require('bcrypt');
var con = require('../conn/conn');

/* GET home page. */
router.get('/', function(req, res, next) {
  if(req.session.flag == 1){
    req.session.destroy();
    res.render('index', { title: 'Verificador de Codigo OTP', message : 'El OTP ya fue Generado anteriormente' , flag : 1});
  }
  else if(req.session.flag == 2){
    req.session.destroy();
    res.render('index', { title: 'Verificador de Codigo OTP', message : 'Por favor regitrar OTP antes de ingresarlo.', flag : 0});
  }
  else if(req.session.flag == 3){
    req.session.destroy();
    res.render('index', { title: 'Verificador de Codigo OTP', message : 'El OTP no esta habilidado.', flag : 1});
  }
  else if(req.session.flag == 4){
    req.session.destroy();
    res.render('index', { title: 'Verificador de Codigo OTP', message : 'Incorrecto OTP.', flag : 1 });
  }
  else{
    res.render('index', { title: 'Verificador de Codigo OTP' });
  }
   
});

//Handle POST request for User Registration
router.post('/auth_reg', function(req, res, next){

  var OTP = req.body.password;
  var password = req.body.password;
  

  if(password !=null){

    var sql = 'select * from user where OTP = ?;';

    con.query(sql,[OTP], function(err, result, fields){
      if(err) throw err;

      if(result.length > 0){
        req.session.flag = 1;
        res.redirect('/');
      }else{

        var hashpassword = bcrypt.hashSync(password, 10);
        
        var sql = 'insert into user(OTP,password,fecha) values(?,?,NOW());';

        con.query(sql,[OTP, hashpassword], function(err, result, fields){
          if(err) throw err;
          req.session.flag = 2;
          res.redirect('/');
        });
      }
    });
  }else{
    req.session.flag = 3;
    res.redirect('/');
  }
});


//Handle POST request for User Login
router.post('/auth_login', function(req,res,next){

  var OTP = req.body.password;
  var password =req.body.password;

  var sql = 'select * from user where OTP = ?;';
  
  con.query(sql,[OTP], function(err,result, fields){
    if(err) throw err;

    if(result.length && bcrypt.compareSync(password, result[0].password)){
      req.session.OTP = OTP;
      res.redirect('/home');
    }else{
      req.session.flag = 4;
      res.redirect('/');
    }
  });
});


//Route For Home Page
router.get('/home', function(req, res, next){
  res.render('home', {message : 'Welcome, ' + req.session.OTP});
});

router.get('/logout', function(req, res, next){
  if(req.session.OTP){
    req.session.destroy();
    res.redirect('/');
  }
})

module.exports = router;
