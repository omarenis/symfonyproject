<?php

namespace App\Controller;

use App\Entity\Personne;
use App\Repository\PersonneRepository;
use Doctrine\ORM\EntityManagerInterface;
use JsonException;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class PersonneController extends AbstractController
{

    /**
     * @var PersonneRepository
     */
    private PersonneRepository $personneRepository;
    /**
     * @var UserPasswordEncoderInterface
     */
    private UserPasswordEncoderInterface $passwordEncoder;
    /**
     * @var EntityManagerInterface
     */
    private EntityManagerInterface $entityManager;
    /**
     * @var JWTTokenManagerInterface
     */
    private JWTTokenManagerInterface $jwtTokenManager;
    private ?string $token;
    public function __construct(PersonneRepository $personneRepository, UserPasswordEncoderInterface $passwordEncoder, EntityManagerInterface $entityManager, JWTTokenManagerInterface $jwTTokenManager)
    {
        $this->personneRepository = $personneRepository;
        $this->passwordEncoder = $passwordEncoder;
        $this->entityManager = $entityManager;
        $this->jwtTokenManager = $jwTTokenManager;
        $this->token = null;
    }

    /**
     * @Route("/signup", methods={"POST"}, name="signup_personne")
     * @param Request $request
     * @return JsonResponse
     */
    public function signup(Request $request): JsonResponse{
        $response = new JsonResponse();
        try {
            $data = json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);
            $user = new Personne();
            $user->setNom($data['nom'])->setPrenom($data['prenom'])->setTelephone($data['telephone']);
            $user->setEmail($data["email"])->setPassword($this->passwordEncoder->encodePassword($user, $data["password"]));
            $this->entityManager->persist($user);
            $this->entityManager->flush();
            $response->setStatusCode(Response::HTTP_OK);
            $response->setData(["response" => "user successfully added"]);
        } catch (JsonException $e) {
            $response->setStatusCode(Response::HTTP_BAD_REQUEST);
            $response->setData(["error"=> "bad request format"]);
        }
        return $response;
    }

    /**
     * @Route("/api/login", methods={"POST"}, name="login_personne")
     * @param Request $request
     * @return JsonResponse
     */
    public function login(Request $request) : JsonResponse{
        $response = new JsonResponse();
        echo($this->token);
        if ($this->getUser()){
            $response->setStatusCode(Response::HTTP_BAD_REQUEST);
            $response->setData(["data" => "user already logged in"]);
            return $response;
        }
        try {
            $data = json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);
            $user = $this->personneRepository->findOneBy(["email" => $data["email"]]);
            if ($user) {
                if ($this->passwordEncoder->isPasswordValid($user, $data["password"]) === true){
                    $response->setStatusCode(Response::HTTP_OK);
                    $this->token = $this->jwtTokenManager->create($user);
                    $response->setData(["token" => $this->token]);
                }
                else {
                    $response->setStatusCode(Response::HTTP_PROXY_AUTHENTICATION_REQUIRED);
                    $response->setData(["error" => "password mismatch with user credentials"]);
                }
            } else {
                $response->setStatusCode(Response::HTTP_FORBIDDEN);
                $response->setData(["error" => "user not found"]);
            }
        } catch (JsonException $e) {
            $response->setStatusCode(Response::HTTP_BAD_REQUEST);
            $response->setData(["error"=> "bad request format"]);
        }
        return $response;
    }
}
