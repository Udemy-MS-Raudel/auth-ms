import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayoad } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  
  private readonly logger = new Logger('AUTH SERVICE')

  constructor(private readonly jwtService: JwtService){
    super();
  }

  async onModuleInit() {
    await this.$connect();
    this.logger.log('MONGO-DB CONNECTED');
  }

  async findOne(email: string){
    const user = await this.user.findUnique({
      where: {email}
    })
    return user;
  }

  async signJWT(payload: JwtPayoad){
    return this.jwtService.sign(payload);
  }

  async registerUser(registerUserDto: RegisterUserDto){
    const {email, name, password} = registerUserDto;

    const user = await this.findOne(email);
    if(user){
      throw new RpcException({
        message: `User with email:${email} already exist`, 
        status: HttpStatus.BAD_REQUEST
      })
    }

    const newUser = await this.user.create({
      data: {
        email, 
        name,
        //Un hash es mejor porque es mas dificil o casi imposible de recuperar por u hacker
        password: bcrypt.hashSync(password, 10)
      }
    })
    const {password: __, ...rest} = newUser;
    
    return {
      user: rest,
      token: await this.signJWT({...rest})
    };
  }

  async loginUser(loginUserDto: LoginUserDto){
      const {email, password} = loginUserDto;

      const user = await this.findOne(email);
      if(!user){
        throw new RpcException({
          message: `User with email:${email} does not exist`, 
          status: HttpStatus.BAD_REQUEST
        })
      }

      const isMatch = bcrypt.compareSync(password, user.password);
      if(!isMatch){
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Invalid credentials'
        })
      }

      const {password: __, ...rest} = user;
      
      return {
        user: rest,
        token: await this.signJWT({...rest})
      }

  }

  async verifyToken(token: string){
    try {
      const {iat, exp, ...user} = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      //Asi puedo reenviar un nuevo token con la misma informacion del usuario y este tendra otra fecha de expiracion
      return {
        user: user,
        token: await this.signJWT(user)
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid token'
      })
    }
  }
  
}
